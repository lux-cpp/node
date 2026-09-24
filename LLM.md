# node — a running Lux node (a chain in a plugin, decided by BLS certificates)

`luxd` (and every brand's daemon built on `run()`: `zood` is this node on Zoo's
specs) runs a network's chain: its EVM is **cevm run as a plugin** over the same
ZAP protocol the Go node speaks to its plugins, its heights are decided by
**α-of-n BLS certificates** over a **mesh of real TCP links** proven by the
post-quantum validator handshake, and it serves the chain over **JSON-RPC**.

A height is decided on **Go's rule, as lux-rs/node runs it**: one proposer a
window from Go's proposervm windower, one signature a height through a durable
journal, the lowest live block that can still reach α. An imported chain —
blocks read off an export, no certificates under them — is continued by the
**anchor**: α validators sign the tip they imported, and build on it.

```
$ curl -s -X POST -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' \
    http://127.0.0.1:19850/v1/chain/c/rpc
{"id":1,"jsonrpc":"2.0","result":"0x7a69"}
```

## The network is a file, not a convention

A validator set derived from an index and a count is a private convention: it
agrees only with copies of itself told the same numbers. The set is a file, the
one the Rust node reads:

```
luxd --data DIR --publish                      # once per validator
luxd --committee FILE --peers a:p,b:p,... [--data DIR] [--produce MS]
     [--mesh-host H] [--import-chain-data PATH]
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

Fewer than four validators certify nothing, which has nothing to do with the
file: a Quasar certificate is refused outright below `kMinBFTCommittee` = 4
seats (f = (n−1)/3 is 0 there), and `verify(Certificate)` calls that floor. A
committee of one is what an archive runs as: it serves the chain, refuses
transactions at the door, and — importing — stays gated.

## Layer decomposition (each layer independently testable)

```
  run        run(spec)          src/run.cpp — flags, keys, committee, the plugin,
                                 the RPC, the engine loop; what a brand's main calls.
  engine     Engine             src/engine.cpp — the height rule and the anchor,
                                 one pass at a time (step), never waiting on a peer.
  windower   Windower           src/windower.cpp — Go's proposervm schedule, and
                                 the header a proposer signs.
  statement  Statement /        src/statement.cpp — the two 226-byte messages a
             Certificate        validator signs (vote, anchor), the one rule a
                                 certificate is held to.
  journal    Journal            src/journal.cpp — one statement a height, on the
                                 device before the key is used.
  ledger     Ledger, gate, held src/ledger.cpp — the certificate every accepted
                                 block was accepted on, the import gate, the block
                                 last signed.
  host       Host               include/lux/node/host.hpp — Mesh + transport, no
                                 consensus state.
  mesh       Mesh               src/mesh.cpp — bind, accept (own thread), dial,
                                 sweep; the PQ greeting decides who a link is.
  transport  MeshVoteTransport  per-link ZAP framing, typed handlers by seat,
                                 one eviction rule.
  vm seam    VM / Block         include/lux/node/vm.hpp — what a chain is.
  plugin     plugin::Chain      src/plugin.cpp — a chain in another process, over ZAP.
  rpc        Rpc                src/rpc.cpp — /v1/chain/<alias>/rpc, relayed to
                                 the plugin's own server; transactions taken there
                                 are relayed across the mesh.
  consensus  REUSED             lux-cpp/consensus — the canonical vote message,
                                 the BLS domain, the Quasar floors.
```

## The height rule

Go's (luxfi/consensus engine/chain, B1: the α-of-K certificate is the only
decider). No rounds and no locks: Go deleted its Tendermint braid in
luxfi/consensus d13b4559, and it does not come back. Each clause below is ported
from **lux-rs/node v0.2.2 (c1e764b)**, cited file:line, and keeps its semantics;
the constants are the same numbers.

| clause | C++ | Rust |
|---|---|---|
| **Windower**: one proposer per (height, slot), MT19937-64 seeded `chainSource ^ height ^ Reverse64(slot)`, stake-weighted heap over validators sorted by node id — Go's windower.go:153/271-317, held to windower_test.go's vectors | `Windower::expected` | proposer.rs:79-236 |
| **Slot clock**: windows since this validator took the height up; a proposal from a slot past `slot+EARLY(1)` is taken only if its slot is within `SKEW(2)` windows of this validator's wall-clock slot (windows since the tip's timestamp); once it has run, the local clock moves up to it and never past the wall-clock slot | `slot_of`, `wall`, `proposed` | engine.rs:455, 723-726, 776-782, 789 |
| **A proposal is signed and checked**: ML-DSA-65 over `chain ‖ parent ‖ SHA-256(set ‖ parent ‖ height ‖ slot ‖ 0x42 ‖ key ‖ block)`, context `lux-node-proposal-v1`, verified against the slot's expected proposer before a byte is parsed | `proposal_header`, `proposed` | proposer.rs:45-77, engine.rs:727-742, host.rs:280 |
| **Build only in your window**, only while nothing is live, bound or built at the height, and not while f+1 verified votes name a block you lack (until the retry gives up — then build) | `offer` | engine.rs:923-972 |
| **One signature per height**: every statement goes through the journal first; a standing one is said again, never replaced | `say`, `Journal` | journal.rs:174, host.rs:221-270, engine.rs:1013-1020 |
| **Converged winner**: after a settle window (window/5, clamped 150 ms–2 s) with no new block, sign the lowest-id live block that can still reach α — its verified votes plus every validator not yet heard from | `vote` | engine.rs:977-1038 (the α filter :996-1002) |
| **Sibling caps**: every signed block that executes is live, within `EACH` (16) a proposer and `SIBLINGS_MAX` (64) a height; past either, the highest id nothing holds goes (and is rejected), a block a vote names always has room | `room` | engine.rs:130-131, 801-817 |
| **One settle deadline per height**: an arrival restarts the settle window only until `SETTLE_MAX` after the first | `stir` | engine.rs:884-889 |
| **The retry**: re-send the bound vote, re-push your own block and the one you signed, doubling from 2×settle to 16 s; the first live sibling resets it, a new link or a sibling beside the one signed brings it forward (no attempt counted); 8 attempts, then ask | `retry`, `live`, `hurry` | engine.rs:526-530, 862-899, 1106-1141 |
| **Decide** on α verified votes for a block held and executed; the certificate is over this node's own position; a vote that signed other roots under the id is let go | `decide` | engine.rs:1052-1096 |
| **Catch-up**: f+1 validators heard at later heights, a certificate for a block not held, or an exhausted retry → ask every peer once a window; each record's certificate is checked against this committee, the block against it, before the chain executes it | `behind`, `answered`, `serve` | engine.rs:1148-1453, mesh.rs:499-560 |

**Wire.** A statement is ZAP msg 62, `bytes(message 226) ‖ bytes(node 20) ‖
bytes(sig 96)` — lux-rs/node's vote frame, so a Rust validator reads a C++ vote.
A proposal is msg 59, `1 ‖ height ‖ slot ‖ sig(3309) ‖ block`; an ask is msg 57
and its answer 57|0x80; a transaction is msg 58 — Rust's ids and layouts. The
greeting is still the LP-10602 handshake with 4-byte framing, which Rust does not
speak, so the two do not share a link yet.

**Why it is safe.** Two certificates at one height need α signers each, so
2α − n > f signers in both — an honest validator signing twice at one height,
which the journal refuses. The winner rule, the retry and the anchor decide which
statement an honest validator makes, never whether it makes two. A height whose
honest validators are bound to different blocks, none able to reach α, stays
uncertified: the price of one signature a height (Go: "unrecoverable",
engine.go:1716). With one seat of five down, α = 4 is every seat that is up.

**Hardening beyond the rule.** A statement is taken only on its signer's own
link (nobody relays a vote), and a link whose statements fail their signature
spends `JUNK_EACH` turns a settle window; an answer is taken only to the
question this node asked that peer; a gated node asks for two records, not a
batch.

## The anchor — continuing an imported chain

An export carries blocks and no certificates. A node that read one holds a tip
no quorum spoke about (Go: proposervm's missing outer index, which "MUST NOT be
treated as a caught-up validator until … rebuilt from certified peer state").
The **import gate** says so: `<data>/uncertified`, written and synced BEFORE the
plugin reads the export whenever `--import-chain-data` is given, read at every
start. While it stands the node builds nothing and signs no block. It still
executes, so it can accept what others certify.

When every validator imports the same export, nobody can certify anything on
it. The anchor is the way out, and it is ONE statement:

```
message (226 bytes, the canonical vote message's layout):
  0   tag          18   "LUX/chain/anchor" 00 00
  18  version       2   3 (kQuorumCertVersion), big-endian
  20  role          1   1 (kQCFinality)
  21  chain        32   the chain id every committee line is entitled on
  53  height        8   T, the imported tip's height, big-endian
  61  round         4   0
  65  block        32   H, the imported tip's id
  97  parent       32   zero
  129 state root   32   zero
  161 payload root 32   zero
  193 set root     32   the committee's validator-set root (Go SetRoot)
  225 accept        1   1
signature: BLS12-381 min-pk, the consensus vote ciphersuite
           (BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_), over the 226 bytes
```

- **Domain separation** is the tag. A vote is the same layout under
  `LUX/chain/vote/v2\0`; the tags differ at byte 10, so a signature over one is
  never a signature over the other (statement_test signs an anchor on (799, H)
  and checks it fails as a vote for block H at 799). A reader refuses an anchor
  whose round, parent, state or payload axes are not zero, so a (chain, T, H,
  set) has exactly one anchor message.
- **One signature per height still holds.** The slot — chain at 21, height at
  53, round at 61 — sits where a vote's does, so the anchor goes through the same
  journal as a vote and takes height T's slot: a validator that already signed
  anything at T cannot anchor there (it waits for a block certified on its tip),
  and one that anchored T never signs a block at T.
- **Who signs**: a gated validator, once, at its own tip (T, H). It is sent as a
  statement (msg 62) and re-sent on the retry schedule — at once, then doubling
  from 2×settle to 16 s — and at once when a peer joins.
- **The certificate**: α = signer_floor(Quasar, n) distinct committee signatures
  on the SAME message, aggregated — the one rule every certificate is held to
  (`verify(Certificate)`: the committee's chain and set root, n ≥ 4, α signers,
  stake past ⅔, one aggregate pairing). Anchor signatures on another (T, H) never
  count toward it.
- **What it does**: the certificate is written to `<data>/ledger` as the record
  at height T (block H), synced; then the gate is removed and the removal
  synced. The node is a validator from T+1.
- **A validator that was not there** (down, or late) asks its peers from its tip
  (T, count 2); the anchor record at T lifts its gate when it names its own tip,
  and a certified T+1 on its tip does the same. A validator that imported a
  different tip signs a different message, never reaches α, and is never lifted
  by the others' records: correct, and safe.
- **A restart** with the flag still set closes the gate again, and the engine
  lifts it at once when the ledger already holds a certificate on the tip.

For the Rust node: `Slot::read` accepts the anchor tag beside the vote tag (the
journal is otherwise unchanged); `gate.rs`'s lift gains the anchor certificate
as a way out; the ledger's first record may be an anchor. Nothing else moves.

## The mesh is not the quorum, and it is not formed once

`connect_mesh` reaches as many configured peers as it can within one deadline
and returns how many; it never demands all of them. `run()` does not exit when a
quorum is not yet reachable: it says so and goes on, and every other window
`sweep` hands the transport the links the acceptor proved and dials each higher
seat that holds none — so a validator that starts before its peers, or restarts,
is met again (lux-rs/node host.rs sweep).

Per pair, the lower seat dials and the higher accepts. The acceptor runs on its
own thread: it takes a connection, answers the LP-10602 greeting as the
responder (each read bounded by `kPeerIoTimeoutMs`), and queues the proven seat;
a stranger that connects and says nothing holds that thread for a timeout and
never the engine. A second proven link from one seat REPLACES the first: a
restarted validator proves its name afresh, and only the holder of that key can.

The mesh listens on `--mesh-host` (default 127.0.0.1, like `--rpc-host`); a
validator whose peers are other pods runs with `--mesh-host 0.0.0.0`. Its own
`--peers` entry is the address the others dial — in a cluster a Service
address the pod does not hold — so it is not what the pod binds. A host that is
not an IPv4 address is refused before anything starts. A peer's address may be
a name: it is resolved at every dial, so a pod that comes back at another
address is found. `mesh_formation_test` [F] meets two 0.0.0.0-bound hosts over
the machine's outward address, and shows a 127.0.0.1-bound one is not there.

## What one hostile peer can do (and what it costs)

One eviction rule, in `MeshVoteTransport::dead`: a stream that closed, a framing
violation, a socket that will not take a write — the peer is dropped. The link's
frame cap is 2 MiB of block plus a proposal's head (mesh.rs LINK_MAX), far under
ZAP's 16 MiB, and only a validator that proved its seat reaches the reader.
Per link and pass, at most 8 proposals and 256 statements are queued; a
proposal's ML-DSA signature is checked before it is parsed; a frame refused once
is remembered for the height; refused frames spend `JUNK_EACH` turns per
(proposer, link) a settle window.

## Concurrency model

The engine, the host, the transport and the plugin link are driven by ONE
thread, `run()`'s loop. The acceptor thread shares only a locked queue of proven
links. The RPC answers on its own threads and takes the chain lock (`guard`) for
every call into the chain; the engine takes the same lock around each VM call and
never while it waits.

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
ctest --test-dir build -L node --output-on-failure   # this repository's 17
./scripts/cluster.sh build/luxd build/bin/cevm       # 5 luxd PROCESSES over cevm, 12 transactions
./scripts/cluster.sh build/luxd build/bin/cevm 2     # ...with validator 2 held down
./scripts/cluster.sh build/luxd build/bin/cevm 2 6   # ...continuing an export of 6 blocks
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
- `wire_vector_test` — the formats node owns end to end, written as literal
  bytes from the spec and compared against a socket the real transport wrote:
  the 359-byte statement frame (msg 62, Rust's vote frame), the greeting's
  framing, and the 193-byte consensus vote frame the transport still carries.
- `mesh_transport_test` — what one hostile or dead socket can do: oversize
  announce + flood, an over-cap frame, vote-then-hang-up, an unwritable peer, and
  that eviction is per-peer.
- `mesh_formation_test` — setup is bounded (an absent peer, and a stranger that
  connects and says nothing, each cost a deadline), partial (2 of 3 report 1), and
  slot-checked (claims {0,0,9} against slots {0,1} admit exactly one peer).
- `windower_test` — Go's proposer schedule, held to windower_test.go's vectors;
  the header a proposer signs moves with every field it binds.
- `statement_test` — the vote and the anchor, their domain separation, the
  statement frame, the certificate rule (α of five, not three; not over another
  message, set or chain), the journal both kinds go through (one slot, one
  statement, a torn tail cut back, a second holder refused), the ledger, the
  held proposal and the gate.
- `engine_test` — one validator against a scripted peer, each refusal against a
  control that shows it is the thing tested.
- `live_test` — five validators on real sockets, each on its own thread: the
  anchor on Zoo mainnet's tip and blocks on it; one seat down; one that imported
  another tip; one that restarts and catches up.
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

Clean under ThreadSanitizer (`-DNODE_SANITIZE=thread`, run under `setarch -R`;
instrumentation covers node + consensus, never blst/bls): `statement`,
`mesh_transport`, `mesh_formation`, `engine` and `live` report no race — the
last with five engines, five acceptor threads and a restart in one process.

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

## What runs, and what it was run against

Measured on the build pod (2026-09-24), node at this branch, cevm main 244b7cb9,
consensus 9928599:

| | evidence |
|---|---|
| Go's proposer schedule | `windower_test`: height 1 slots 0..23, 720, 721 and heights 1/2 slot 0 are windower_test.go's answers |
| five validators continue an imported chain | `live_test` [1]: five seats import Zoo mainnet's tip (799, `0xd6f92941…f72b8`), all five anchor it, all five accept the same blocks 800..806 |
| one seat down | `live_test` [2]: four of five carry the chain to 803; heights 800 and 802, whose first window is the missing seat's, are built in a later window; the seat starts, lifts its gate on the anchor its peers hold, catches up and goes on |
| a seat that imported another tip | `live_test` [3]: the other four anchor and build to 805; it anchors nothing, decides nothing, stays gated at its own tip, and its journal holds one statement — its own anchor |
| a seat restarts | `live_test` [4]: its journal reopens, its peers meet it again, it takes 804..808 on certificates and goes on to 811 with the others |
| what one validator refuses | `engine_test`: a proposal signed for another's window is never parsed; a refused block is never signed; a gated node builds nothing in its own window and signs only its anchor; a chain that refuses to build does not stop it — each against a control |
| processes, the cevm plugin, Zoo mainnet's export | zooai/node `test/live.sh`: five `zood` processes import `zoo-mainnet-200200.rlp` and every one anchors 799 at `0xd6f92941…f72b8`; with seat 3 down four anchor, and seat 3 started later anchors on the ledger answer; a seat that imported the export cut at 798 anchors nothing and stays at 798 |
| processes, the cevm plugin, transactions | `scripts/cluster.sh`: five `luxd` on the local chain, twelve transactions relayed across the mesh, every validator at height 12 with the same block hash at every height; with seat 2 held down, the same with four |
| processes, the cevm plugin, an import continued | `scripts/cluster.sh luxd cevm -1 6`: cevm alone builds six blocks into an export (`local_export`); five `luxd` import it, all five anchor height 6, and blocks 7..12 are built on it with the same hash at every height on every seat; with seat 3 held down (`… 3 6`), four anchor and build the same |

Building 800 on Zoo mainnet's own export over cevm needs a transaction from a
funded Zoo account, and there is no key to sign one with here: building on an
imported tip over cevm is proven on the local chain's export, and on Zoo's tip
by `live_test`.

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
BINDS the axis when it executes in process (`Binding::Executed`); a chain in a
plugin cannot hand it the root, so `run()` signs `Transport`, as Go does. What is gained is that divergent execution cannot hide. What it
costs is interop: a signed message that binds the root is not the message Go
signs for the same block, so a C++ and a Go validator cannot form one quorum
until Go binds it too. Stated here because it is a protocol difference, not an
implementation detail.

## Not here yet

- **Rust wire.** Statements, proposals, asks and transactions are Rust's ids and
  layouts; the greeting is not, so a C++ and a Rust validator do not share a link.
- **A certificate in Go's codec.** The ledger keeps `message ‖ signers ‖
  aggregate`; Go's `cert_codec.go` shape is what a mixed network will need.
- **Pruning.** The journal keeps every statement and reads them all at start
  (226 bytes a height); entries below the accepted tip can go.
- **A split height.** A height whose honest signers are bound to different
  blocks, none able to reach α, stays uncertified (Go: "unrecoverable"; left to
  Nova, which this node does not run). With one seat of five down, α is every
  seat that is up, so one late sibling at the wrong moment is enough.
- **Sampling.** Every validator is polled; there is no photon sampling.
- **P, X, Q and Z.** The `VM` seam is what they plug into; only the EVM runs.

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

Three places USE them: the luxd peer path (below), node's own mesh greeting
(LP-10602, "The link two validators run before a frame"), and the proposal a
window's proposer signs (ML-DSA-65, "The height rule"). Votes, anchors and
certificates are classical BLS.

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
  divergent EVM stalls a height instead of hiding. A chain linked in process
  can take this; the tests' chains do.
- `Transport` leaves the execution axes empty, which is what luxd signs: Go's
  proposervm returns `ids.Empty`, and a Go voter does not execute the block it
  votes on. A C++ node that binds the root inside a live Go network produces a
  message Go DROPS rather than disputes. `run()` signs this: its chain is a
  plugin, whose verify is what refuses a block that does not execute.

Joining luxd takes `Transport` until Go binds the axis too, at which point this
collapses back to one answer.
