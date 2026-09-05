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
ctest --test-dir build --output-on-failure    # 44: node, consensus, and cevm's parity gates
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
| an RLP export imports and matches Go | the canonical `lux-testnet-96368.rlp`: 218 blocks, 219 senders recovered, every link walked, tip `0x722e2b39ae8973ab5d94b51451623352650b728e411ce0261c5efcd23aa381a5` and state root `0x4e19366fcc65d7ddd0b803bfbd7537f0c0ddc5d190c3ded40712408fcb137f35` — the same two values Go's import of the same bytes produced. `zoo-testnet` (84), `zoo-mainnet` (799) and `spc-mainnet` import the same way |
| an imported node refuses to validate | `import_test`: the engine proposes nothing, follows nothing, and never asks the chain to build; `luxd` prints NOT A CAUGHT-UP VALIDATOR and parks |

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
- **PQ is absent.** No ML-KEM-768 handshake, no ML-DSA-65 identity or block
  signing. `luxcpp/pqclean` and `luxcpp/lattice` are not linked by node. Quasar
  here is classical blst. Nothing here pretends otherwise.
- **The peer handshake is 4 plaintext bytes** (see below).

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

## Reading a chain back (`--import-chain-data`)

The C-chain speaks two encodings. **ZAP** is the serialization everything in this
stack uses — votes, blocks on the wire, the frame. **RLP** is what the C-chain
hands to Ethereum, and a chain's history leaves it as an *export*: a bare
concatenation of RLP-encoded blocks with no envelope, no index and no length
prefix. `luxd --import-chain-data PATH` reads one. The flag is spelled Go's way
because it is the same flag: Go passes it into the C-Chain's config and the VM
reads the export at startup, before the chain serves anything, and a second run
of an unchanged flag is a no-op rather than a failure. One runbook, three
implementations.

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
was never even **asked** to build, with the un-imported chain as the control.
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

What is NOT done is every place they would be USED: the peer handshake is still
four plaintext bytes, NodeID is still an index, and blocks are still signed with
classical BLS. Those are the work; the crypto under them is not.

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
