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

## The network is a file, not a convention

`noded` used to take `--index I --n N --base-port P` and DERIVE its validator set
from those three numbers. That set was a private convention: it could only ever
agree with copies of itself that had been told the same three numbers, and an
operator had no way to describe one network to more than one implementation. The
flags are gone. What replaces them is the file the Rust node already reads:

```
noded --data DIR --publish                      # once per validator
noded --committee FILE --peers a:p,b:p,... [--data DIR]
```

One line per validator, three hex fields, `#` starts a comment:

```
<identity>  the ML-DSA-65 public key it is NAMED by
<key>       the 48-byte compressed BLS public key it votes with
<proof>     its proof of possession over node ‖ key, CHECKED on load
```

**One node, one name — and the chain is in the PROOF.** The id is
`ids.NodeIDScheme.DeriveMLDSA` at chain ZERO — `SHAKE256` over
`left_encode`-framed `"NODE_ID_V1" ‖ 0 ‖ scheme ‖ key`, first 20 bytes — which
is the value Go's `node.Node` gives itself (`MyNodeID = DeriveNodeID(ids.Empty)`)
and the one the link handshake re-derives to check a peer. A node does not
change its name when it joins another chain.

What is scoped is the ENTITLEMENT: the possession proof is signed over
`chain ‖ node ‖ key`, so a line published for one network authorises nothing on
another. `--chain-id` decides which chain a file is good on. Put the chain in
the name instead and a node has as many names as it has chains; leave it out of
both and a committee line is a bearer credential on every network at once
(LP-10603).

Weight is 1 per validator. **File order is kept**, because `--peers` is
positional against it — the third address belongs to the third line, and the
entry at this node's own seat is where it listens. A node finds ITSELF by name:
its seat is where its own identity sits, so two processes cannot be told they are
the same validator, and no validator can be handed a seat it holds no key for.

Refused, and by the same clauses the Rust reader refuses: a file with no
validators, a line that is not three fields, a field that is not hex, a validator
listed twice. Possession is refused at the door — `Committee::validators()` goes
through `consensus::admit`, so a member whose proof does not bind its name to its
key never reaches the gate.

**The names and the root are the same in three languages.**
`test/committee/four.txt` is four lines this daemon published, entitled on the
local C-Chain (`evm::chain_id(31337)` = `c066f0c6…c51ede87`):

```
C++   Committee::read(...).root()      de34e8d1…dfa696e7
Rust  lux_node::engine::Committee       de34e8d1…dfa696e7
Go    luxfi/validators SetRoot          de34e8d1…dfa696e7
```

and the four names agree one for one in all three. Computed, not asserted: the
Go values come from a program importing `luxfi/validators` and `luxfi/ids`
unmodified, the Rust one from a path dependency on `lux-rs/node`. Go also checks
every proof over `chain ‖ node ‖ key` with its own `bls.VerifyProofOfPossession`
and answers "proof holds on this chain" for all four — and "PROOF DOES NOT HOLD"
for the same file read as a committee of another network.

Rust computes the same names and the same root and then refuses the set with
`PopInvalid`: it still checks the node-bound `node ‖ key` proof, where the file
now carries the chain-scoped one. That is the remaining half of the LP-10603
port, in flight there.

`test/committee/elsewhere.txt` is those same four validators publishing for a
different chain: the same names, and not one of them admitted here.

Two validators still cannot decide anything, which has nothing to do with the
file: `WaveConfig::feasible(2)` sizes the committee at `kMinBFTCommittee` = 4 and
asks for `two_thirds_count(4)` = 3 confirming votes, which 2 reachable validators
can never cast; and `cert.cpp` refuses a Quasar certificate outright below 4
seats. Run two processes on a two-line committee and they publish, seat
themselves, agree on the set root, form the mesh — and report `height 1 NOT
CERTIFIED before deadline`. Four is the floor.

## Layer decomposition (decomplected — each layer is independently testable)

```
  rpc          Rpc / serve_eth   NEW  src/rpc.cpp, src/eth.cpp — HTTP JSON-RPC at
                                       /v1/chain/<alias>/rpc. Knows JSON, no chain.
  chain        evm::Chain        NEW  src/evm.cpp — the C-Chain: genesis, mempool,
                                       execution through cevm, the real MPT root.
                                       The ONLY unit that knows evmc/intx/StateDB.
  export       import_chain_data NEW  src/import.cpp — the C-chain's EXTERNAL
                                       format (RLP) read back: ids recomputed,
                                       links walked, tx tries rebuilt. Knows the
                                       Ethereum block, not consensus.
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
  luxd peer    Peer               NEW  src/peer.cpp — the OTHER wire: one link to a
                                       real luxd. TLS 1.3 (peer_tls), then the
                                       strict-PQ handshake, then p2p + a vote.
  pq handshake pq::run_initiator  NEW  src/pq_handshake.cpp — ML-KEM-768 session and
                                       ML-DSA-65 identity, transport-agnostic; the
                                       frame lambdas in peer.cpp are its one binding.
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
ctest --test-dir build --output-on-failure    # 54: node, consensus, and cevm's parity gates
                                             # (evm-gethdiff skips without a geth to diff)
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

- `plugin_test` — a REAL Go VM plugin, started the way the Go node starts one
  and driven through initialize, set-state, get, parse. Skips with a notice when
  no plugin path is given, which is the one test here that can pass by doing
  nothing — run it with one.
- `pq_vector_test` — the validator link (LP-10602) held to a handshake the GO
  node produced: `test/pq/handshake.json` carries the RESP frame
  `mesh/peer.RunPQHandshakeConn` wrote, the INIT frame it accepted, and the
  session key it derived. Both transcript prefixes are rebuilt here and proven
  by the signatures over them, the binding and the key are recomputed, and a
  vector with one byte moved is refused. `--against host:port` regenerates it
  against a live Go responder.
- `committee_test` — the network description: the parse, the four refusals, the
  seat, the root, and the possession proof. The fixtures are REAL FILES and half
  of them were published by the Rust node, so "both read this" is a fact about
  one artifact; the expected root is Go's, computed by a program importing
  `luxfi/validators`, so the encoder is never compared to itself.
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
- `hostile_decode_test` — the two decoders that take bytes from strangers,
  `Tx::decode` (any `eth_sendRawTransaction` caller) and `Chain::parse` (any
  peer), fed bytes a stranger would send. Both had a way to end the process: an
  RLP length bound written as `size < head + len` wraps at the 8-byte long form
  and accepts a declared 2^64-1, and a block's transaction count was reserved
  before a single transaction was read — 893 GB at `sizeof(Tx)`. Each case was
  confirmed to FAIL against the unfixed decoder first, which is the only way to
  know a decoder test is testing anything: the obvious assertions pass either
  way, because `Tx::decode` rejects the overflow for an unrelated reason and
  `parse` frees the reservation on its way out. So the bound is asserted on
  `rlp::item` directly, and the allocation on `VmPeak`.
- `pq_handshake_test` — the strict-PQ peer handshake, in two halves. The first
  is known-answer: the hexadecimal in it was printed by Go
  (`ids.NodeIDSchemeMLDSA65.DeriveMLDSA`, `kem.HashTranscript`,
  `KEMSession.DeriveAEADKey`) and nothing in this repository can produce those
  strings, which is exactly what a round trip between two C++ ends cannot give
  you. The second is a real `socketpair` against a responder transcribed from
  `RespondHandshake`, and its load-bearing assertion is that both ends derive
  the SAME session key: the responder builds its canonical bytes from its own
  fields while the initiator recovers them from a parse, so an asymmetric
  transcript shows up as two different keys rather than as a handshake that
  reports success.

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
- **The validator-set root** is `luxfi/validators SetRoot`, and the committee
  file feeds it the same bytes the Go P-chain path would — the 20-byte node id,
  weight big-endian, and the key UNCOMPRESSED.

## A chain in another process

The Go node does not link its chains in; it runs each as a separate program and
speaks ZAP to it. Every chain that is not the C-Chain — P, X, Q, Z and the rest
— exists as one of those programs today, so a host that can run them does not
need a port of each. `plugin::Chain` is a `node::VM`, so the engine cannot tell
which side of the boundary its chain is on.

PROVEN AGAINST A REAL PLUGIN, the shipped EVM binary
(`build/plugins/mgj786NP7uDwBCcq6YwThhaN8FLyybkCa4zBWTQbNgmK6k9A6`, v0.18.19).
It came up under this host and answered:

```
last accepted 0xbb2e5a9273dc3c0562b7cdda58c8a75c5708ee8382d7de7e90f0f94e195fbaba  height 0
580 bytes, parent 0x0000…0000
state root    0x275cf305b6494e020a03167b7c3ca616ae5058aa56537b523a4deb754f4327f6
```

`plugin_test /path/to/plugin` (or `LUX_VM_PLUGIN=`) runs it. With no plugin it
says so and passes.

### The interop contract, as the Go node performs it

Nobody had written this down; it is `vms/rpcchainvm/factory.go` and
`runtime/subprocess/runtime_zap.go` read off the code, and every step below cost
a failed run to find:

1. The NODE binds a bootstrap listener — TCP on 127.0.0.1:0, or a unix socket
   under a temp dir when `LUXD_VM_UNIX_SOCKET=1`.
2. It execs the plugin with the parent environment plus `VM_TRANSPORT=zap`,
   `VM_RUNTIME_ENGINE_ADDR=<that address>` and `LUX_VM_RUNTIME_ENGINE_ADDR=`
   (the pre-rename key, for plugins built before it).
3. The PLUGIN binds its own address and dials the bootstrap listener, writing
   `[4-byte BE length][4-byte BE protocol][address as text]`, length counting
   the version and the address.
4. The node refuses a protocol that is not its own — 42 — and then **writes one
   byte, 0x01**. Skip it and the plugin logs `failed to read handshake ack: EOF`
   and exits, and the address it just reported answers nothing.
5. The node dials that address. From there it is ZAP:
   `[4-byte BE length][1-byte type][payload]`, every request and response
   payload beginning with a 4-byte big-endian request id; a response is the
   request's type with 0x80, an error adds 0x40.
6. `MsgInitialize` (1) with `XChainID`, `CChainID` and `UTXOAssetID` at their
   FULL 32 bytes even when the network has none — a plugin refuses a short one:
   `initialize xChainID: invalid hash length: expected 32 bytes but got 0`.
7. `MsgSetState` (2) to Bootstrapping and then Ready BEFORE building. Asked to
   build while still bootstrapping, the EVM plugin dereferences nil and the call
   comes back as `panic in handler`.

Three findings came out of making that work:

- **The shipped plugin cannot use a unix socket.** It infers the network from
  the address and dials `tcp` on any of them:
  `dial tcp: address /tmp/luxd-vm-*/vm.sock: missing port in address`. That is
  why Go's socket path is opt-in, and this host matches Go rather than
  preferring the better transport.
- **`zap-cpp-core` could not read a Go plugin's error, and now can.** Go writes
  the error body RAW after the request id (`api/zap/transport.go:507`); the C++
  server wrote and the client read a length-prefixed string, self-consistently,
  so every C++-to-C++ test passed and every error from a Go peer arrived as
  `truncated error response` with the message gone. Fixed in both halves on
  `lux-cpp/zap-cpp-core` branch `net/error-body-is-raw`, with a conformance case
  that pins the bytes rather than a round trip — a round trip is exactly what
  missed it. `plugin.cpp` uses `ZapClient` again; the workaround is gone. **This
  node needs that branch**: the header is consumed from the working tree.
- **The execution state root does not cross this boundary.** `BlockResponse`
  carries id, parent, bytes, height and timestamp and no root, because Go's
  proposervm answers `ids.Empty` for that axis. A plugin-hosted chain must
  therefore be driven with `Binding::Transport`; `plugin::Remote::root()`
  answers the empty id and says so rather than inventing one. The root above was
  read out of the block's own bytes.

## The link two validators run before a frame

The mesh used to greet with four plaintext bytes: an index the dialer CLAIMED.
Anyone who could reach the port could claim a seat, and the code said so — safety
was argued from the vote gate downstream, never from the link. That is gone.

A link is now LP-10602: ML-DSA-65 over a running transcript in each direction,
ML-KEM-768 in the responder's, a session key from both, and the role in the FIPS
204 context so a captured signature is not a signature in the other direction.
The seat is where the committee says the PROVEN name sits, so an address that
turns out to belong to someone else is refused rather than believed, and a
validator nobody seated is refused even though its handshake completes.

Held to Go, not to itself: a C++ initiator completed a handshake against
`mesh/peer.RunPQHandshakeConn` with the C++ daemon's own keypair, both ends
derived `6c7de15f…0c5ba4f5`, and each derived the other's name identically. That
exchange is `test/pq/handshake.json`, made against the published libraries:
`luxfi/node`'s `mesh/peer` as the responder (it resolves `luxfi/crypto v1.20.9`,
though its handshake never calls it) and `luxfi/crypto v1.20.11` on this side.

Three things about it worth knowing before touching it:

- **`mldsa65_sign_ctx` takes the MESSAGE before the context** — and two builds of
  libluxcrypto have shipped with those two the other way round from each other.
  The published library is message-first (and `v1.20.9` has no `_ctx` pair at
  all); `~/work/lux/crypto` was for a while a stale snapshot with no remote whose
  pair is context-first. This file has been on both sides of it, and the note
  further down — "the C ABI arguments were transposed" — was right the first
  time: it is the snapshot that is the outlier.

  **A swap does not look like a swap.** FIPS 204 caps a CONTEXT at 255 bytes and
  says nothing about message length, so with the two exchanged everything up to
  255 bytes still signs and verifies and everything longer returns -2 — which
  reads as a message-size limit. Measured against the published build:

  ```
  message length     1  100  254  255  256  512  3199  6512  9615  16384
  correct order      0    0    0    0    0    0     0     0     0      0
  swapped            0    0    0    0   -2   -2    -2    -2    -2     -2
  ```

  It is emphatically NOT `LUX_GPU_MLDSA_MSG_LEN_CAP`. That constant lives in an
  accelerator plugin which is not loaded here; `backend.Resolved()` never returns
  GPU without one, so `batchVerifyGPU` returns `(false, nil)` at its first gate
  and the `ErrInvalidArgument` hard-error path is unreachable. With the order
  right, the published library signs and verifies 16 KiB without complaint.

  **Nothing in Go can catch it**, which is why it survived: `mesh/peer`'s
  handshake signs through `cloudflare/circl` directly and never calls the C ABI.
  That ABI exists for C++, Rust, Python and TypeScript, so no Go test exercises
  it. Only a C caller can guard the order, so `pq_handshake_test` round-trips a
  6512-byte sign and verify through it — and says out loud that a 255-byte one
  proves nothing. Fixed in `luxfi/crypto` v1.20.11.
- **Signing is deterministic, and it had to be made so.** LP-10602 mandates it
  and Go signs that way (`mldsa65.SignTo(..., randomized=false)`), but the C ABI
  offered only `SignCtx(rand.Reader, ...)`, so two signatures over one message
  differed and a published handshake could be checked and never reproduced.
  `mldsa65_sign_ctx_det` is in `luxfi/crypto` v1.20.10, with its argument order
  corrected to match its siblings in v1.20.11. The vector carries both secrets
  and both signatures are RE-MADE and compared — the responder's included, which
  is Go's own bytes.
- **The link binds a peer's name at chain zero,** which is what Go does
  (`peer.go verifyPQIdentityBinding`) and what a name is. The chain the link
  carries scopes the session; the chain a committee line carries scopes the
  entitlement; neither scopes the name.

Two things found while pinning the set root, both in trees this repo only reads:

- **Go's own root depends on how Go was built.** `SetRoot` hashes whatever bytes
  the caller hands it, and the caller hands it
  `crypto/bls.PublicKeyToUncompressedBytes`, which returns blst's 96 bytes under
  `//go:build cgo` and the COMPRESSED 48 under `//go:build !cgo`. The same source
  over the same four validators: `cd75055e…f40ba23f` with cgo, `87db179d…8b2ba615` without. Two
  Go nodes built differently commit to different roots and would refuse each
  other's votes. Measured by building one program both ways.
- **A validator used to have two names.** The committee named it
  `keccak256(mldsa_pub)[..20]`; the link handshake named the same key
  `SHAKE256("NODE_ID_V1" ‖ 0 ‖ scheme ‖ key)[..20]`. It has one now, and it is
  the second, which is `pq::derive_node_id` here and
  `ids.NodeIDScheme.DeriveMLDSA` in Go. There is one derivation in this tree and
  the committee calls it.

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
| an RLP export imports and matches Go | the canonical `lux-testnet-96368.rlp`: 218 blocks, 219 senders recovered, every link walked, tip `0x722e2b39ae8973ab5d94b51451623352650b728e411ce0261c5efcd23aa381a5` and state root `0x4e19366fcc65d7ddd0b803bfbd7537f0c0ddc5d190c3ded40712408fcb137f35` — the same two values Go's import of the same bytes produced. `zoo-testnet` (84), `zoo-mainnet` (799) and `spc-mainnet` (10) import the same way |
| …and at mainnet size | `lux-mainnet-96369.rlp`, 1.2 GB: 1,082,780 blocks and 1,229,884 senders recovered in ~4.5 min, peak RSS ~4.2 GB, tip `0x32dede1f…61f0`. The export is MAPPED, not read into a buffer — but every block it ingests is kept in memory, so an import is bounded by the same absence of persistence the rest of this node has |
| an imported node refuses to validate | `import_test`: the engine proposes nothing, follows nothing, and never asks the chain to build, through either door; `luxd` prints NOT A CAUGHT-UP VALIDATOR and parks |
| both doors are one reader | on a live `luxd`, `--import-chain-data` reads the canonical export to tip `0x722e2b39…81a5`, and `admin_importChain` given the same file on the same node answers `{"blocks":0,"skipped":218}` at the same tip — resume, across the two doors, off one head |

| precompiles work from contract code | SHA-256, RIPEMD-160 and IDENTITY match Python's hashlib byte-for-byte, called from deployed bytecode on the live chain |
| DELEGATECALL delegates | a proxy's storage takes the write; the implementation's own storage is untouched |

NOT REAL YET — named, not hidden:

- **No rollback of a speculative execution.** cevm's `commit()` clears the
  journal, so a block cannot be reverted once its root is computed. A height that
  fails to certify leaves the state ahead of the last accepted block, and `noded`
  STOPS rather than build on it. Fail-secure, and the next thing to close.
- **An import does not derive state.** The blocks and the tip are real and
  checked; the EVM state behind them is not, because an export carries no genesis
  allocation to execute from. `eth_getBalance` after an import answers from the
  configured genesis, not from the imported chain — which is the second reason
  such a node must not validate, and why it parks instead.
- **No recovery from an import.** Go rebuilds the missing outer index from
  certified peer state (`enterOuterBackfill`); this node refuses and stops there.
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
- **PQ reaches the luxd peer path and nothing else.** `lux-join` now runs the
  ML-KEM-768 + ML-DSA-65 handshake against a real luxd (below). Block signing
  is still classical blst, and node's OWN internal mesh handshake is still 4
  plaintext bytes — two different wires, and only the first is post-quantum.
- **The internal mesh handshake is 4 plaintext bytes** (see below).

## The bug that was here, and why no gate saw it

cevm's `EvmcStateHost::call()` decided whether there was anything to execute by
asking StateDB for a code size, and treated "nothing to run" as success. A
precompile has no code there, so every call to one from inside contract code
returned `EVMC_SUCCESS` with an empty output and no gas charged — a contract
calling SHA-256 got 32 zero bytes and no error. `DELEGATECALL` and `CALLCODE`
matched no branch at all, so the callee's code never ran: every proxy and
upgradeable contract, reporting success and writing nothing. And the code was
read from `msg.recipient` rather than `msg.code_address`, which is the same
account for a plain CALL and the wrong one for exactly those two kinds.

None of it was visible to the seven geth-parity gates, because the contract case
in `evm-block-root-parity` calls no precompile and delegates to nothing. A gate
that passes while the engine computes a non-Ethereum state root is the failure
mode worth remembering: the bug was not that something errored, it was that
nothing did.

Fixed in cevm (`blue/cpp-node-cevm-live`), with `evm-host-precompile-parity`
added and registered so it cannot come back quietly. That gate was confirmed to
FAIL against the old host — `status=0` on every case — before being committed as
passing.

## A deliberate divergence from Go, and its cost

Go leaves the vote's execution axes EMPTY: `proposervm`'s
`ExecutionStateRoot()` returns `ids.Empty`, so a Go validator certifies the root
only indirectly, through a block hash that happens to commit to it. This node
BINDS the axis. What is gained is that divergent execution cannot hide. What it
costs is interop: a signed message that binds the root is not the message Go
signs for the same block, so a C++ and a Go validator cannot form one quorum
until Go binds it too. Stated here because it is a protocol difference, not an
implementation detail.

## Reading a chain back (two doors, one reader)

The C-chain speaks two encodings. **ZAP** is the serialization everything in this
stack uses — votes, blocks on the wire, the frame. **RLP** is what the C-chain
hands to Ethereum, and a chain's history leaves it as an *export*: a bare
concatenation of RLP-encoded blocks with no envelope, no index and no length
prefix. `luxd --import-chain-data PATH` reads one. The flag is spelled Go's way
because it is the same flag: Go passes it into the C-Chain's config and the VM
reads the export at startup, before the chain serves anything, and a second run
of an unchanged flag is a no-op rather than a failure. One runbook, three
implementations.

A node is asked to read an export in **two** ways and there is **one** reader.
`--import-chain-data PATH` at startup and the `admin_importChain` RPC while it
runs are both calls to `import_chain_data`; `serve_admin` (`src/eth.cpp`) is nine
lines and `noded`'s flag is shorter, and neither decodes anything. Go has that
exact shape — `admin_api.go:84` and `vm.go:628` both call
`importBlocksFromFile` — and it is worth keeping because the alternative is the
usual one: the flag grows a reader, the RPC grows another, and a single binary
ends up with two answers to what a block is.

```
$ curl -s -X POST -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"admin_importChain",
             "params":["…/lux-testnet-96368.rlp"]}' \
    http://127.0.0.1:41898/v1/chain/C/rpc
{"blocks":218,"skipped":0,"transactions":219,"heightBefore":"0x0",
 "heightAfter":"0xda","frontier":"0x0",
 "tip":"0x722e2b39ae…81a5","stateRoot":"0x4e19366f…7f35"}
```

`frontier` rides along in the answer, so a caller polling the door that filled
the chain is told in the same breath that the node has decided none of it.

**The lock and the checkpoint.** `Rpc` holds THE chain lock for the whole of
every method call, which is what Go spells `vmLock.Lock()` at the top of
`ImportChain` — a read that arrives mid-height waits for it. Every 4096 blocks
(Go's `defaultCommitInterval`) the reader stops and tells its door where it has
got to. Go commits the state trie there and moves the accepted-block pointer in
the same step "so there's no crash window where state is persisted but
acceptedBlockDB is stale"; here the pointer is moved by `ingest`, and the reader
READS IT BACK and refuses to go on unless it names the block just ingested — so
a checkpoint can only ever report a height the chain already holds. Resume is
the same fact from the other side: the head on entry is where the last run of
*either* door stopped, the file is re-walked from the front with every check
re-run, and only blocks above the head are ingested.

**What is proven, and what is only carried.** Every hash compared here is one
this node computed: a block's id is `keccak(rlp(header))` over the header's own
bytes; block N's parentHash must equal the id computed for block N−1, walked over
every block rather than sampled; the body's transactions rebuild the header's
`transactionsRoot` as a Merkle-Patricia trie; the uncle list hashes to
`ommersHash`; and every transaction is decoded and its sender RECOVERED with
secp256k1 — which also refuses another chain's export, since a transaction binds
its chain id.

The `stateRoot` is the one thing NOT proven, and naming it is the point. An
export carries blocks, not state: deriving these roots means executing every
transaction from the genesis ALLOCATION, which an export does not contain (the
canonical lux-testnet export's genesis alloc is not in `lux/state`). So the roots
are read from the headers as claims, and this node ends up knowing a tip whose
state it did not compute.

### And therefore it is not a validator

Reading an export moves the tip and produces **no certificate under it**. Go
names the same state in `vms/proposervm/vm.go` — an inner chain restored without
its outer index — and says what has to follow: such a chain "will NOT build
blocks and MUST NOT be treated as a caught-up validator until the outer index is
rebuilt from certified peer state." A node that imports and then proposes signs
an ancestry it never verified, which is worse than one that cannot import at all.

The rule is one predicate in one place. `VM::frontier()` is a VALUE — the highest
height this node itself decided — and `Engine::may_sign()` compares it to the
tip. It is asked at the top of `settle()`, the single door every signed message
passes through, and again in front of `build()`/`parse()`, because building is
executing and a refusal behind the execution would already have run a block
against state this node never derived. `evm::Chain::ingest` moves the tip and
deliberately does not touch the frontier; `BlockImpl::accept` — reached only on a
verifying quorum certificate — is the only thing that does.

`import_test` drives the engine over an imported chain and asserts that the chain
was never even **asked** to build, with the un-imported chain as the control —
and does it again over a chain filled through the RPC door, because the refusal
is a property of the chain and not of the door that filled it.
`noded` says the same thing out loud and parks: RPC keeps answering, so the
imported history is readable and the state is visible rather than silent.

```
node 0: import tip 0x722e2b39ae…81a5 height 218 time 1746815479
node 0: import state root 0x4e19366f…7f35 (carried from the header — an export holds blocks, not state)
node 0: import 218 blocks ingested, 0 already held, 219 transactions recovered
node 0: NOT A CAUGHT-UP VALIDATOR — tip is height 218, this node's own decisions stop at height 0
```

Recovery — rebuilding those heights from certified peer state — is **not here**.
Go has `enterOuterBackfill`; this node has the refusal and no way out of it but a
fresh start. Said plainly rather than hidden behind a tip that looks healthy.

## Scope (honest)

Does: real listen/accept/connect mesh, bounded and partial; ZAP framing with
non-blocking reassembly and per-peer eviction; real BLS quorum-cert finality
across threads and processes; real EVM execution with a geth-identical MPT root;
transaction and block gossip; live JSON-RPC.

Does NOT yet, in the order it matters:

- **Authentication on node's OWN mesh.** The index handshake is 4 plaintext
  bytes. A stranger that connects first takes a validator's inbound slot, which
  is a liveness DoS even though safety holds (votes self-identify by pubkey and
  the gate verifies BLS + set membership). This is the internal mesh, not the
  luxd peer path: that one is authenticated, by the ML-DSA-65 handshake above.
  Go ZAP has an X25519 + ML-KEM-768 hybrid handshake with AEAD; node uses only
  the frame layer — no reqID, no multiplexing, no ZAP RPC.
- **A PQ responder.** `pq::run_initiator` has no counterpart, because nothing
  in this node is dialled by a luxd. Adding one before something accepts a
  connection would be another file that compiles and is never called, which is
  the state this whole section is about.
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

## This file

`LLM.md` is the canonical document and is tracked here. `AGENTS.md`, `GEMINI.md`
and `CLAUDE.md` are symlinks to it, kept on disk and NOT tracked: they hold no
content of their own, and tracking them would only be a way for the repository
to carry one file under four names and eventually disagree with itself. After a
fresh clone:

```
ln -sf LLM.md AGENTS.md && ln -sf LLM.md GEMINI.md && ln -sf LLM.md CLAUDE.md
```

## Post-quantum: what is available, and what is not

The primitives are here and they work. lux-crypto — which this node already
links — ships ML-KEM-768 and ML-DSA-65 behind a C ABI at NIST level 3
(`mlkem_keygen/encap/decap`, `mldsa_keygen/sign/verify`, `mode = 3`). Verified
on Linux: the KEM round-trips to an agreeing shared secret, ML-DSA-65 signs at
3309 bytes and verifies, and one flipped signature byte fails verification.
Nothing needs to be vendored from `luxcpp/pqclean` or `luxcpp/lattice` for
either.

One place now USES them, and it is the one that faces a real network. The rest
is unchanged: node's own mesh handshake is still four plaintext bytes, its
internal NodeID is still an index, and blocks are still signed with classical
BLS.

## The strict-PQ peer handshake, and the two ways it was wrong

`Peer::connect` runs `pq::run_initiator` over the TLS session it has just
established and before a single p2p byte — luxd's `RunPQHandshakeConn`, the
initiator half. `pq_handshake.cpp` had been written for this and never called,
and "written and never called" turned out to conceal two defects that no amount
of reading had caught.

**The C ABI arguments were transposed.** `mldsa65_sign_ctx` and
`mldsa65_verify_ctx` take the message before the context; this file declared
them the other way round. They have C linkage, so the declaration and the
definition need not agree for the program to link — the arguments simply
arrive in the wrong registers. The effect is not a subtly wrong signature: the
transcript arrives where FIPS 204 expects a context, contexts are capped at 255
bytes, and signing fails outright every time. The peer path could never have
completed a handshake even once.

**The AEAD transcript carried the INIT twice.** Go's `resp.canonicalBytes()` is
the response alone; `resp.transcriptPrefix(init)` is the whole INIT followed by
those same fields. The port built one from the other, so `bindAEADTranscript`
received `INIT ‖ INIT ‖ RESP` where Go builds `INIT ‖ RESP`. This one is
silent. Both ends complete, both bind each other's NodeID, neither reports
anything — and the two session keys differ. Nothing consumes the key yet on
either side (luxd stores it as `pqAEADKey` and encrypts nothing with it), so it
would have sat there looking healthy until the AEAD wrapper landed and broke
every link at once.

Both were confirmed against a REAL Go responder before and after: a program
calling `peer.RunPQHandshakeConn` on the ingress side of a socket, against this
node's initiator. With the transposed arguments, signing fails and Go reports
`read PQ INIT: EOF`. With the doubled transcript, both sides succeed and report
different AEAD keys. Fixed, the two derive the same 32 bytes, which means every
byte of both canonical messages, the binding, the TupleHash and the key
derivation agree across the two implementations. The same check over TLS
(luxd's own `tls_config.go` settings, group 0x11ec) has `lux-join` complete the
handshake against Go end to end.

**Whether it runs is a genesis fact, not a negotiation.** Go's
`profileRequiresPQHandshake` runs the handshake for `ProfileStrictPQ` and
`ProfileFIPS` and skips it otherwise, and a chain whose genesis carries no
`securityProfile.json` pin boots classical-compat. luxfi/genesis pins profileID
1 for mainnet, testnet and local/localnet and profileID 2 for devnet, so
`lux-join` maps network id 3 to permissive and everything else to strict-PQ.
Guessing desyncs the link on its first frame in either direction, which is why
the axis is a `Peer::connect` parameter and never a default.

One consequence is easy to miss: `verifyPQIdentityBinding` replaces the peer's
TLS-cert NodeID with the ML-DSA-derived one the moment the handshake completes.
So does this side. A quorum vote gossiped after the handshake names the
key-derived NodeID, because that is the name luxd now files this validator
under; naming the certificate hash there would address a validator it no longer
has.

The handshake's own framing is `[4-byte BE length][payload]`, capped at 16 KiB
— the same shape as the p2p wire and a different rule: p2p counts its tag byte
in the length and caps at 2 MiB, this counts nothing extra and has no tag.
Three wires, one repository, three caps.

Two things about the build were the same defect wearing another hat.
`src/keccak.cpp` was in no target either, so the library had the handshake's
symbols and not the SHAKE256 under them — nothing noticed until something
linked. And `nm build/luxd` was the wrong place to look for the result: `luxd`
is `src/noded.cpp`, which has no peer path and reports zero `peer` symbols as
well as zero `pq` ones. `lux-join` is the
binary that carries this path; it went from 0 handshake symbols to 15.

## Whose message this node signs

`Engine::Binding` decides, and it is a named choice because the two answers are
mutually exclusive — validators that disagree about it do not form a quorum,
their signatures simply fail against each other's message.

- `Executed` binds `execution_state_root` to what this node's EVM produced, so a
  divergent EVM stalls a height instead of hiding. `noded` uses this.
- `Transport` leaves the execution axes empty, which is what luxd signs: Go's
  proposervm returns `ids.Empty`, and a Go voter does not execute the block it
  votes on. A C++ node that binds the root inside a live Go network produces a
  message Go DROPS rather than disputes.

Joining luxd takes `Transport` until Go binds the axis too, at which point this
collapses back to one answer.
