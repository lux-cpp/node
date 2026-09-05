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

    // The RPC name this chain answers to. A chain is BORN with its name, the
    // same way it is born with its id: the Lux primary network's EVM is "C",
    // and a sovereign L1 (Zoo, Hanzo) has its own EVM under its own name and no
    // C-Chain at all. Leaving this to the binary would let one node present the
    // same chain under two names, which is how a network ends up answering for
    // a chain it does not have.
    std::string   alias     = "C";
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
    std::string   alias() const override;
    std::shared_ptr<node::Block> build() override;
    std::shared_ptr<node::Block> parse(std::span<const std::uint8_t>) override;
    std::shared_ptr<node::Block> get(const Id&) const override;
    void          prefer(const Id&) override;
    Id            last_accepted() const override;
    std::uint64_t last_accepted_height() const override;

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
