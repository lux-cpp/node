// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// evm.hpp — the C-Chain: a node::VM whose blocks are executed by cevm.
//
// This is where the node stops being a finality daemon and becomes a chain.
// Everything above it (consensus, the vote mesh, the quorum cert) already
// worked; what was missing is a block whose CONTENT means something. Here a
// block is a list of transactions, executing it moves real Ethereum state, and
// the 32 bytes the validators sign are the Merkle-Patricia-Trie root that
// execution produced — the same root luxfi/geth computes for the same block
// (cevm's evm-block-root-parity gate holds it there byte-for-byte).
//
// THE ROOT IS COMPUTED, NEVER COPIED. A peer sends block BYTES; this node
// parses them, runs the transactions through its OWN cevm instance, and derives
// the root itself. `VotePosition::execution_state_root` is therefore a fact
// about this node's execution, not a claim the proposer made. Two validators
// that execute differently produce different positions, sign different
// messages, and never form a quorum — divergence shows up as a stalled height
// rather than as a fork. That is the whole reason the root belongs in the
// signed message.
//
// Layering: node knows `VM`; only this translation unit knows evmc, intx and
// StateDB. The chain state lives behind a pimpl so cevm's headers stay out of
// node's public surface — P and X plug in at the same seam without inheriting
// the EVM's dependencies.

#pragma once

#include "lux/node/vm.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace lux::node::evm {

// A 20-byte account address. Spelled as a plain array here so node's public
// headers never need evmc; the translation unit converts at the boundary.
using Address = std::array<std::uint8_t, 20>;

// A 256-bit quantity, big-endian. Balances and values are the only place node
// needs one, and it only ever moves them between cevm and JSON hex.
using Word = std::array<std::uint8_t, 32>;

// What a chain is born holding: its id, its block gas limit, and who starts
// with what. Rendered from the C-Chain genesis JSON Go reads (`chainId`,
// `gasLimit`, `alloc`).
struct Genesis {
    std::uint64_t chain_id  = 0;
    std::uint64_t gas_limit = 30'000'000;
    std::vector<std::pair<Address, Word>> alloc;  // address → starting balance
};

// A decoded, signature-verified transaction. Construction is the verification:
// `decode` returns nullopt for anything malformed, unsigned, replay-bound to
// another chain, or whose signature does not recover — so a Tx that exists is a
// tx whose sender was RECOVERED from its signature, never one that named itself.
struct Tx {
    Id                        hash{};      // keccak256(raw), the eth tx hash
    Address                   sender{};    // RECOVERED via secp256k1, not asserted
    Address                   to{};
    bool                      create = false;
    Word                      value{};
    Word                      gas_price{};
    std::uint64_t             gas   = 21'000;
    std::uint64_t             nonce = 0;
    std::vector<std::uint8_t> data;
    std::vector<std::uint8_t> raw;         // exactly the bytes the caller sent

    // Decode an RLP-encoded signed transaction (legacy, EIP-2930 or EIP-1559)
    // and RECOVER the sender. `chain_id` is checked wherever the encoding binds
    // one (EIP-155 legacy, and typed transactions always), so a transaction for
    // another chain is refused rather than replayed here.
    static std::optional<Tx> decode(std::span<const std::uint8_t> raw, std::uint64_t chain_id);
};

// A BLOCK OUT OF THE CHAIN'S PAST, read back from an export.
//
// The C-Chain has two encodings and this is the other one. A block this node
// builds is a ZAP frame whose id is the keccak of exactly those bytes; a block
// the chain EXPORTS is an Ethereum block, and its id is the keccak of its
// header's RLP. Both are the same five facts — parent, height, timestamp, root,
// transactions — carried in the format that names the block for whoever is
// reading it, so `id` and `bytes` come from the reader rather than from a
// re-encoding here. Re-deriving them would mean re-choosing an encoding the
// exporter already chose, and one disagreement about it would name a different
// block.
//
// `root` IS A CLAIM, and the whole of this type turns on that. A built or
// followed block's root is what this node's own cevm produced; a past block's
// root is what its header says, because reading an export executes nothing. A
// chain holding these therefore knows a tip whose state it has not derived —
// which is exactly why `Chain::frontier()` stops below them.
struct Past {
    Id                        id{};         // keccak(rlp(header)) — recomputed by the reader
    Id                        parent{};     // its header's parentHash
    Id                        root{};       // its header's stateRoot — a claim, not a result
    std::uint64_t             height    = 0;
    std::uint64_t             timestamp = 0;
    std::vector<Tx>           txs;          // senders RECOVERED, never asserted
    std::vector<std::uint8_t> bytes;        // the block's own RLP, verbatim
};

// The C-Chain. Owns the EVM state, the mempool, and every block it has built or
// accepted.
//
// EXECUTION HAPPENS AT BUILD/PARSE, before consensus votes — which is Go's order
// too: `BuildBlock` runs the block and the header carries the root it produced,
// so consensus decides on an already-executed result. What this node does NOT
// yet have is a speculative execution it can roll back: cevm's `commit()` clears
// the journal, so a snapshot taken before a block cannot be reverted after its
// root is computed. A height that fails to certify therefore leaves the state
// ahead of the last accepted block, and `Chain::advance` halts the node rather
// than build a second block on top of it. Fail-secure, and named in LLM.md as
// the next thing to close.
class Chain final : public node::VM {
public:
    // The chain's whole mutable state, defined in the translation unit that owns
    // the EVM. Declared here (not below) because the block type is what advances
    // the tip on accept, and it has to be able to name this.
    struct State;

    explicit Chain(Genesis genesis);
    ~Chain() override;

    Chain(const Chain&) = delete;
    Chain& operator=(const Chain&) = delete;

    // ── node::VM ────────────────────────────────────────────────────────────
    Id            chain_id() const override;
    std::string   alias() const override { return "C"; }
    std::shared_ptr<node::Block> build() override;
    std::shared_ptr<node::Block> parse(std::span<const std::uint8_t>) override;
    std::shared_ptr<node::Block> get(const Id&) const override;
    void          prefer(const Id&) override;
    Id            last_accepted() const override;
    std::uint64_t last_accepted_height() const override;
    std::uint64_t frontier() const override;

    // Take one block of history read from an export. It must extend the tip by
    // exactly one height, and that is the only thing this checks — whether the
    // block belongs to THIS chain's past is the reader's question, because only
    // the reader has the file's own genesis to close the ancestry against.
    //
    // Ingesting moves the tip and produces NO certificate, so it leaves
    // frontier() behind — deliberately, and permanently until consensus catches
    // up. Throws on a block that does not extend the tip; a chain that quietly
    // accepted a gap would report a height it cannot walk down from.
    void ingest(Past);

    // ── the EVM's own questions, which only its RPC asks ────────────────────
    std::uint64_t eth_chain_id() const noexcept;

    // Read committed state. These read the SAME StateDB execution writes, so a
    // balance served over RPC is the balance the state root commits to — there
    // is no second copy to drift.
    Word          balance(const Address&) const;
    std::uint64_t nonce(const Address&) const;
    std::vector<std::uint8_t> code(const Address&) const;
    Word          storage(const Address&, const Word& key) const;

    // The root of the last ACCEPTED block — what the last quorum cert certified.
    Id            state_root() const;

    // Admit a transaction to the mempool. Returns its hash, or nullopt if it did
    // not decode / recover / bind this chain. The caller has already been told
    // nothing about the sender at this point: the mempool only holds txs whose
    // signature produced their sender.
    std::optional<Id> accept_tx(std::span<const std::uint8_t> raw);

    // Re-admit a transaction that arrived from a peer over the mesh. Same
    // verification, different door — a peer is trusted with bytes and nothing
    // else, exactly as it is for votes.
    std::optional<Id> accept_tx_from_peer(std::span<const std::uint8_t> raw);

    std::size_t pending() const noexcept;

    // Raw bytes of every tx in the mempool, for gossip. Copies, because the
    // caller writes them to sockets while the chain keeps building.
    std::vector<std::vector<std::uint8_t>> pending_raw() const;

    // A block this chain knows, by height — what eth_getBlockByNumber serves.
    std::shared_ptr<node::Block> at_height(std::uint64_t) const;

    // Transactions of an accepted block, in order (for eth_getBlockByNumber).
    std::vector<Tx> block_txs(const Id& block) const;

private:
    std::unique_ptr<State> st_;
};

}  // namespace lux::node::evm
