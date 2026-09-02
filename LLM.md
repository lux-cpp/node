# node — a running Lux node (a C-Chain executed by cevm, decided by BLS consensus)

`noded` runs a **C-Chain**: it executes real EVM blocks through **cevm**, decides
them with **BLS quorum-certificate consensus** over a **mesh of real TCP
sockets** framed by the canonical **ZAP** wire codec, and serves them over
**JSON-RPC**. N validators, each on a real listener, dial each other, take turns
proposing, and independently execute every block before signing it.

**The signed message carries the state root each node's own EVM produced.** One
validator proposes and publishes the block's bytes; every other validator parses
those bytes, runs the transactions through ITS OWN cevm, and derives the root
itself. A quorum certificate is therefore agreement about an executed RESULT, not
about a name — a node whose EVM diverged signs a different message and is simply
not in the quorum, so divergence stalls a height instead of forking it.

```
$ curl -s -X POST -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' \
    http://127.0.0.1:19850/v1/chain/C/rpc
{"id":1,"jsonrpc":"2.0","result":"0x7a69"}
```

## Layer decomposition (decomplected — each layer is independently testable)

```
  rpc          Rpc / serve_eth   NEW  src/rpc.cpp, src/eth.cpp — HTTP JSON-RPC at
                                       /v1/chain/<alias>/rpc. Knows JSON, no chain.
  chain        evm::Chain        NEW  src/evm.cpp — the C-Chain: genesis, mempool,
                                       execution through cevm, the real MPT root.
                                       The ONLY unit that knows evmc/intx/StateDB.
  vm seam      VM / Block        NEW  include/lux/node/vm.hpp — what a chain is,
                                       asked once. P, X, Q and Z plug in here.
  engine       Engine            NEW  src/engine.cpp — execute → decide → accept,
                                       for any VM. Owns the lock discipline.
  node-host    Node2Host         NEW  src/node_host.cpp   — listen/accept/dial the
                                       mesh; own one Party; drive submit/round/pump.
  mesh         MeshVoteTransport  NEW  include/.../mesh_vote_transport.hpp (header-only)
                                       VoteTransport over N peer fds; broadcast→all,
                                       pump→drain all, one eviction rule. Holds a vote
                                       SINK, not a Node — zero consensus knowledge.
  reassembler  FrameReader        NEW  include/.../frame_reader.hpp (header-only)
                                       the ONE place that knows non-blocking framing:
                                       reassembles ZAP frames from recv(MSG_DONTWAIT),
                                       bounded by the frame size its link carries.
  codec/wire   encode/decode_vote REUSE consensus/.../zap/vote_codec.hpp
               Writer/Reader/           zap-cpp-core/.../zap/wire.hpp
               write_frame_locked
  consensus    Node / Wave /      REUSE consensus (the gate, unmodified)
               QuorumCertEngine
  crypto       consensus::bls    REUSE consensus (consensus DST) + blst
  evm          process_block /   REUSE cevm (lib/evm + lib/evm/state)
               StateDB / MPT           the interpreter, the state, the real root
  ecrecover    secp256k1_ecrecover REUSE lux-crypto (a tx's sender is RECOVERED)
```

## What a height is

```
  proposer = height mod n          the turn moves; no node is load-bearing
    build()      execute the mempool through cevm, commit → REAL MPT root
    submit(pos)  REGISTER the block locally .......... before publishing it
    gossip       publish the block's bytes (ZAP kBlockMsgType)
    round/pump   β-confirmation, then sign + broadcast the ACCEPT vote
  followers
    parse(bytes) execute the SAME transactions through THEIR OWN cevm
    submit(pos)  their root, their signed message
    round/pump   sign if their execution agrees
  everyone
    accept()     on a VERIFYING quorum cert: advance the tip and the
                 decided-height frontier
```

Register-before-publish is load-bearing and was learned the hard way: published
first, every follower vote arrived naming a block the proposer had not yet
submitted, the gate turned them away as `RejectedNoSuchBlock`, and a validator
broadcasts its ACCEPT exactly once — so the proposer could not certify the block
it had just made. `Node2Host` additionally BUFFERS votes for a block it has not
registered yet and replays them on the next `submit`, bounded at
`kMaxEarlyVotes`, because the same window exists between two followers.

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
`noded` reads the returned count against `two_thirds_stake_floor`.

Per pair, the lower index dials and the higher index accepts → exactly one
connection per pair. A dialer writes a 4-byte BE index handshake (ZAP `Writer`,
the same encoder the frames use); the acceptor consumes it so the frame stream
starts clean, and matches the claimed index against the slots it is waiting on —
so one connection fills at most the slot it names. Accepts and dials are swept
together each round, so an absent low-indexed peer starves nothing, and the retry
policy lives in the sweep rather than inside the dial. A node with an absent
validator waits out the mesh window before starting consensus: it cannot tell
"not started yet" from "not coming".

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
- `SIGPIPE` is disarmed once, in the one place node writes to a socket — a peer
  that hangs up mid-broadcast used to kill the validator.

## Concurrency model

Share-nothing. Each `Node` is touched by exactly one thread (its host driver).
Mesh setup is the only concurrent phase; the consensus phase is single-threaded
round-robin → deterministic. No application mutex except the per-peer write mutex
required by `write_frame_locked` (uncontended here).

## Build & test (links the reused checkouts, no vendoring)

`luxcpp/consensus` and the `luxcpp` root (blst, `crypto/bls`, `zap-cpp-core`) are
found automatically; `-DCONSENSUS_DIR` / `-DLUXCPP_ROOT` override.

The search matches on `include/lux/consensus/node.hpp`, not on the directory
name, because the name alone is ambiguous: `luxfi/consensus` is the **Go**
implementation and sits beside node in the lux checkout, while the C++ one lives
under `luxcpp`. The header is what distinguishes them.

cevm's dependencies come from Conan, so node is configured with the toolchain
Conan generates for it. CMake says so up front rather than failing later inside
cevm's `find_package(intx)`.

```
conan install ../../luxcpp/cevm -pr ../../luxcpp/cevm/.github/conan/manylinux-relax.profile \
  -s build_type=Release -s compiler.cppstd=gnu20 \
  --output-folder=../../luxcpp/cevm/build-node --build=missing

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE=../../luxcpp/cevm/build-node/build/Release/generators/conan_toolchain.cmake
cmake --build build -j
ctest --test-dir build --output-on-failure    # 42: node, consensus, and cevm's geth-parity gates
./scripts/chain.sh                            # 5 processes serving one C-Chain over JSON-RPC
./scripts/cluster.sh build/noded 19310 5      # 5 real PROCESSES, consensus only
./scripts/cluster.sh build/noded 19310 5 4    # ...with validator 4 held down
```

The four "missing house Conan recipes" recorded in lux-cpp/sdk's notes
(`bls/1.0.0`, `lux-crypto`, `lux-zap-core/0.1.0`, `lux-gpu/0.2.0`) are STALE:
three resolve from the local cache and `lux-gpu` is only required for the Apple
Metal backend, which a Linux build does not select. What genuinely blocked the
build was a one-line cross-platform bug — `luxcpp/gpu`'s `cpu_backend.cpp`
declared lux-crypto's BLAKE3 through an `__asm__` label holding a literal Mach-O
mangled name (`__ZN3lux…`, two leading underscores), so every ELF link of
`libluxgpu` failed. It is now declared in its own namespace and mangled by the
compiler, which is right on every ABI.

**Build against consensus `origin/main`, not the primary working tree.** That
checkout sits on `converge/consensus`, seventeen commits behind, and the API
differs (`consensus::Node` is `consensus::Party`, and its constructor no longer
takes α). Use a worktree pinned to the commit you mean and pass
`-DCONSENSUS_DIR`.

- `frame_reader_test` — the reassembler alone: fragmentation, batching, the
  rejection latch, and the per-link frame cap.
- `wire_vector_test` — the two formats node owns end to end, written as literal
  bytes from the spec and compared against a socket the real transport wrote: the
  4-byte BE index handshake and the 193-byte vote frame.
- `mesh_transport_test` — what one hostile or dead socket can do: oversize
  announce + flood, an over-cap frame, vote-then-hang-up, an unwritable peer, and
  that eviction is per-peer.
- `mesh_formation_test` — setup is bounded (an absent peer, and a stranger that
  connects and says nothing, each cost a deadline), partial (2 of 3 report 1), and
  slot-checked (claims {0,0,9} against slots {0,1} admit exactly one peer).
- `node_cluster_test` — 5 hosts, ephemeral ports, full TCP mesh; asserts **no
  node final before `pump()`**, then all 5 finalize with a verifying cert.
- `node_liveness_test` — a DOWN validator (in every host's configured set, and
  dialled) and a WEDGED-but-present one are both routed around on the wire.

Verified clean under ThreadSanitizer and ASan+UBSan+Leak (run TSan under
`setarch -R`; instrumentation covers node + consensus, never blst/bls).

## Conformance to Go

Go is the network; node conforms to it, and the conformance is tested, not
asserted in a comment.

- **The frame** is `[4-byte BE length][1-byte msg_type][payload]`, `HeaderSize=5`,
  `MaxMessageSize=16 MiB` — byte-identical to `github.com/luxfi/api/zap`. A frame
  captured off a live `noded` socket parses with Go's `zap.ReadMessage` with no
  error and three fields of exactly 32/48/96 bytes, zero trailing.
- **The signed message and the floors** are consensus's, checked against the
  Go-generated corpus by `conformance_test`, which runs in this suite.

## What is real, and what is not (measured, not asserted)

REAL — observed on a running 5-process cluster, not inferred:

| | evidence |
|---|---|
| cevm builds and links into `noded` | `libevm.a` + `libevm-state.a`; `noded` links them |
| the state root is a real Ethereum MPT root | `evm-state-root-parity` and `evm-block-root-parity` pass — byte-identical to luxfi/geth, and they now run in THIS repo's `ctest` |
| genesis root is computed from the allocation | `0x29e1beb5aa…`, identical on every node, changes when the alloc changes |
| blocks execute and finalize | 3507 heights over five processes, every node at the same height |
| the certified root is the executed root | `VotePosition::execution_state_root` = what this node's cevm returned |
| every node executes independently | all five report the same root for a height; the proposer only publishes bytes |
| a transaction is real end to end | signed by `eth-account` (an independent implementation), sender RECOVERED here via secp256k1, balance moved exactly 1 ether, nonce 0→1, root changed `0x29e1beb5…` → `0xd117904d…` |
| contract creation and storage work | a constructor's `SSTORE` is readable through `eth_getStorageAt` |
| JSON-RPC is live | `eth_chainId` → `0x7a69`, `eth_blockNumber` advances off the real pipeline |

NOT REAL YET — named, not hidden:

- **Precompiles are unreachable from contract code, and they fail SILENTLY.**
  This is a cevm bug, not a node one, and it is the sharpest thing on this page.
  `EvmcStateHost::call()` (cevm `lib/evm/state/evmc_host.hpp`) executes a callee
  only when `db_.get_code_size(recipient) > 0`. A precompile has no code in the
  StateDB, so the branch falls through to `return evmc::Result{EVMC_SUCCESS,
  msg.gas, 0}` — **success, empty output, no gas charged**. Measured on the
  running chain: `STATICCALL(0x02)` returns 1 and yields 32 zero bytes where
  SHA-256 was due; `CALL(0x04)` likewise fails to echo its input. `DELEGATECALL`
  and `STATICCALL` are not handled by either branch at all, so they never execute
  the callee's code even for an ordinary contract. Any contract touching
  `ecrecover`/`sha256`/`modexp`/`bn256` computes a different result from geth and
  therefore a different state root — a fork, arrived at without an error. The
  geth-parity gates do not catch it because their contract case does not call a
  precompile. The implementations exist (`cevm::state::call_precompile` in
  `test/state/precompiles.hpp`, and `evm::gpu::precompile::Dispatcher`); the host
  just never dispatches. Fixing it needs cevm's own parity gates re-run, which is
  why it is written down here rather than patched in passing.
- **No rollback of a speculative execution.** cevm's `commit()` clears the
  journal, so a block cannot be reverted once its root is computed. A height that
  fails to certify leaves the state ahead of the last accepted block, and `noded`
  STOPS rather than build on it. Fail-secure, and the next thing to close.
- **No persistence.** State and blocks are in memory; a restart is a new chain.
  `HostConfig::accepted` exists to be seeded from a durable store, and there is
  no durable store.
- **One resident state, so no historical reads.** A `blockNumber` parameter is
  accepted and the tip is answered; the RPC does not reconstruct a past state.
- **`eth_call`, receipts, logs and a fee market are absent**, not stubbed. There
  is no `eth_getTransactionReceipt` returning a fabricated receipt.
- **P, X, Q and Z are not here.** The `VM` seam is what they plug into; only C is
  implemented.
- **The C-Chain is IN-PROCESS, not a plugin.** luxd loads its EVM as a separate
  process over ZAP (`vms/rpcchainvm/zap`, MsgBuildBlock=9 … MsgBlockReject=30).
  This node links cevm directly. The `VM` interface is the seam a ZAP client
  would implement, so the split is a transport change rather than a rewrite.
- **PQ is absent.** No ML-KEM-768 handshake, no ML-DSA-65 identity or block
  signing. `luxcpp/pqclean` and `luxcpp/lattice` are not linked by node. Quasar
  here is classical blst. Nothing here pretends otherwise.
- **The peer handshake is 4 plaintext bytes** (see below).

## A deliberate divergence from Go, and its cost

Go leaves the vote's execution axes EMPTY: `proposervm`'s
`ExecutionStateRoot()` returns `ids.Empty`, so a Go validator certifies the root
only indirectly, through a block hash that happens to commit to it. This node
BINDS the axis. What is gained is that divergent execution cannot hide. What it
costs is interop: a signed message that binds the root is not the message Go
signs for the same block, so a C++ and a Go validator cannot form one quorum
until Go binds it too. Stated here because it is a protocol difference, not an
implementation detail.

## Scope (honest)

Does: real listen/accept/connect mesh, bounded and partial; ZAP framing with
non-blocking reassembly and per-peer eviction; real BLS quorum-cert finality
across threads and processes; real EVM execution with a geth-identical MPT root;
transaction and block gossip; live JSON-RPC.

Does NOT yet, in the order it matters:

- **Peer authentication.** The index handshake is 4 plaintext bytes. A stranger
  that connects first takes a validator's inbound slot, which is a liveness DoS
  even though safety holds (votes self-identify by pubkey and the gate verifies
  BLS + set membership). Go ZAP has an X25519 + ML-KEM-768 hybrid handshake with
  AEAD; node uses only the frame layer — no reqID, no multiplexing, no ZAP RPC.
- **Sampling.** `Node2Host::round` drives the wave from the committee this node
  can *reach* — a connectivity measure, not a poll of anyone's opinion. It is one
  expression, in one place, and photon sampling replaces exactly it.
- **Reconnection.** The peer set is one-shot: no discovery, no backoff, no
  re-dial after an eviction. An evicted peer is gone for the run.
- **Persistence.** `noded` now runs many heights (3507 observed), but the
  frontier, the state and the blocks are all in memory: a restart is a new chain.
  `Party::mark_finalized_through` is called (via `Node2Host::accept`) when a
  height certifies, and `HostConfig::accepted` exists to re-seed it on boot —
  from a durable store that does not exist yet.
- **The ZAP message set.** The link carries three types: votes (`0x11`),
  transactions (`0x12`) and proposed blocks (`0x13`). Go's p2p wire has 26
  (`Get`/`Put`/`PushQuery`/`PullQuery`/`Chits`, the bootstrap and state-sync
  families, the handshake). Note also that Go's p2p framing counts the type byte
  in its length and caps at 2 MiB, whereas the plugin-RPC framing this node uses
  excludes it and caps at 16 MiB — they are two different wires with one name.
