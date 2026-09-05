// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// vm.hpp — the interface a chain implements, and the ONE place node knows what
// a chain is. C (the EVM), P (the platform) and X (the UTXO DAG) differ in what
// they put in a block and how they execute it; they do not differ in these
// questions, so they are asked once, here.
//
// Rendered from Go's block.ChainVM (luxfi/consensus). Every method carries the
// Go name it renders so the two cannot drift apart quietly. Go declares the VM
// twice and the two declarations disagree (engine/chain/block.ChainVM has 15
// methods, core/block.ChainVM 14, union 17, agreement 10); this renders what
// BOTH agree on AND this node drives, which is what lux-cpp/sdk's vm.hpp
// already established. That header is the same surface one layer up and should
// come to include THIS one rather than declare it a second time — sdk depends
// on node, so node is where the definition belongs.
//
// EXECUTION IS NOT OPTIONAL HERE. Go's engine/chain type-asserts a block to
// canonicalCommitter and leaves the execution axes empty when a VM does not
// implement it. A chain whose blocks carry no execution identity is a chain
// whose validators certify a name rather than a result, so `root()` is on Block
// itself: a block that cannot say what state it produced cannot be built.

#pragma once

#include "lux/consensus/quorum_cert_engine.hpp"  // Id, kEmptyId — one definition of an id

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace lux::node {

using lux::consensus::Id;
using lux::consensus::kEmptyId;

// A block. Consensus never reads its contents: it reads where the block sits
// (id, parent, height), what executing it produced (root), and later tells it
// HOW it was decided — accepted, or rejected in favour of something else. Both
// halves, because Go's Decidable has both and a chain told only about the half
// that went its way keeps holding what the other half would have given back.
// Bytes are what a peer receives, and the only thing a peer
// is trusted to send — a receiving node parses and re-executes to derive the
// position itself, rather than taking a peer's word for the height or the root.
struct Block {
    virtual ~Block() = default;

    virtual Id id() const = 0;                                // Go ID
    virtual Id parent() const = 0;                            // Go Parent
    virtual std::uint64_t height() const = 0;                 // Go Height
    virtual std::span<const std::uint8_t> bytes() const = 0;  // Go Bytes

    // The state root this block's execution PRODUCED — Go's
    // canonicalCommitter.ExecutionStateRoot. It is what validators sign over, so
    // it is computed by running the block, never copied from a proposer.
    virtual Id root() const = 0;                              // Go ExecutionStateRoot

    // This node's own execution verdict. False is a refusal to vote, never an
    // error: an honest node does not vote for a block its own execution rejects.
    virtual bool verify() = 0;                                // Go Verify

    // The block is decided. Must be durable before returning — last_accepted()
    // reports it after a restart, and that is what closes the height to a second
    // signature.
    virtual void accept() = 0;                                // Go Accept

    // The block is decided AGAINST: it can never be accepted, so what it was
    // holding goes back. Its transactions return to whatever the next build()
    // draws from, and the state its execution pinned is released.
    //
    // THE TRANSACTIONS ARE THE POINT. They were never refused — they lost a
    // race — and a node that drops them disagrees with every other node about
    // what is still pending, then proposes a block built from that disagreement.
    // Go says the same in three places: platformvm's rejector reissues the
    // block's decision transactions and wakes the builder, xvm's Reject asks
    // each transaction again against the state that actually won and reissues
    // the ones that still hold, and both free the block's pinned state.
    //
    // NOT the answer to a failed verify(). A block this node refused to vote for
    // never entered consensus and never took anything out of the pool; Go drops
    // it where it stands (engine/chain: "built block failed verification —
    // dropping") and calls Reject only on a block that was registered and then
    // lost. Rejecting a dropped block would hand back transactions nobody took.
    //
    // Decided ONCE, either way. accept and reject are each inert after the
    // other, because more than one path can reach a decision — Go guards the
    // same double-decide with pendingBlocks.Decided before it calls either.
    virtual void reject() = 0;                                // Go Reject
};

// The chain itself. An L1, an L2 rollup and an L3 differ in what they put in a
// block and how they settle it — never in these five questions.
//
// A null block is "no", not a failure: nothing to build, not a block, unknown
// id. That is the house form; a genuine boundary failure throws.
struct VM {
    virtual ~VM() = default;

    // The chain's own identity and its RPC name. `alias` is the path segment a
    // JSON-RPC caller reaches it under (Go: /ext/bc/<alias>), so "C", "P", "X".
    virtual Id chain_id() const = 0;
    virtual std::string alias() const = 0;

    virtual std::shared_ptr<Block> build() = 0;                               // Go BuildBlock
    virtual std::shared_ptr<Block> parse(std::span<const std::uint8_t>) = 0;  // Go ParseBlock
    virtual std::shared_ptr<Block> get(const Id&) const = 0;                  // Go GetBlock
    virtual void prefer(const Id&) = 0;                                       // Go SetPreference

    // The DURABLE last-accepted block, read on boot before this node signs
    // anything, and the height that seeds the decided-height frontier.
    virtual Id last_accepted() const = 0;                                     // Go LastAccepted
    virtual std::uint64_t last_accepted_height() const = 0;

    // THE HIGHEST HEIGHT THIS NODE ITSELF DECIDED — the top of the run of
    // blocks that reached the tip through a quorum certificate this node
    // verified, rather than arriving from outside it.
    //
    // On a chain that only ever advanced through accept() this is
    // last_accepted_height() and the question is uninteresting. It stops being
    // uninteresting the moment a chain can be handed history: reading an export
    // moves the tip WITHOUT producing a single certificate under it, so the
    // chain reports a healthy tip while every consensus frontier below it is
    // missing. Go names the same state in vms/proposervm/vm.go — an inner chain
    // restored without its outer index — and says what follows from it: such a
    // chain "will NOT build blocks and MUST NOT be treated as a caught-up
    // validator until the outer index is rebuilt from certified peer state".
    //
    // A VALUE, NOT A FLAG. The chain reports where its decisions stop; whether
    // that is far enough to vote is the engine's rule, stated once there. A
    // boolean here would put the policy in the chain and then have to be kept in
    // step with it — two places, one rule.
    virtual std::uint64_t frontier() const = 0;
};

}  // namespace lux::node
