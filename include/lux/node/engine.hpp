// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// engine.hpp — what turns a VM and a mesh into a chain that advances.
//
// Go calls this engine/chain: the loop that asks the VM for a block, asks
// consensus to decide it, and tells the VM the answer. It is written against
// `VM`, not against the EVM, because that is the whole point — C, P, X, Q and Z
// differ in what a block contains and agree completely on what happens to it.
//
// THE ORDER IS EXECUTE, THEN DECIDE. The block is run before a single vote is
// cast, so the state root is a result rather than a promise, and it is that root
// that goes into the signed VotePosition. Go builds in the same order
// (dummy/consensus.go writes header.Root inside FinalizeAndAssemble, before
// BuildBlock returns) — but Go then leaves the vote's execution axes EMPTY:
// proposervm's ExecutionStateRoot() returns ids.Empty, so a Go validator
// certifies the root only indirectly, through a block hash that happens to
// commit to it. Here the axis is bound.
//
// That is a DELIBERATE DIVERGENCE and it has a consequence worth stating: a
// signed message that binds the root is not the message Go signs for the same
// block, so a C++ validator and a Go validator cannot form one quorum until Go
// binds the axis too. What is gained is that divergent execution can no longer
// hide — two nodes whose EVMs disagree sign different messages and simply fail
// to reach a quorum, instead of both signing a name they each mean differently.

#pragma once

#include "lux/node/node_host.hpp"
#include "lux/node/vm.hpp"

#include <functional>
#include <memory>
#include <mutex>
#include <optional>

namespace lux::node {

// One decided height: the block, and the certificate that decided it.
struct Decided {
    std::shared_ptr<Block>            block;
    lux::consensus::QuorumCert        cert;
};

// THE LOCK DISCIPLINE, IN ONE PLACE. The VM is single-threaded and the RPC
// answers from other threads, so calls INTO the VM take a lock. Waiting for
// consensus does not: submit / round / pump / isFinal touch the Party and the
// transport, never the chain, and holding the chain across that wait is what
// makes an RPC endpoint go silent for the length of every height. Which is not a
// hypothetical — it is what this daemon did first, and why the rule lives here
// rather than at each call site.
class Engine {
public:
    // The engine drives the VM; it does not own the mesh, which outlives it.
    // `guard` is the chain's lock — the same one the RPC holds while it answers.
    Engine(std::unique_ptr<VM> vm, Node2Host& host, std::mutex& guard);

    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;

    // Build the next block, execute it, and drive consensus until its position
    // carries a verifying quorum certificate — then accept it. Returns the
    // decided height, or nullopt if the deadline passed without a certificate.
    //
    // A nullopt is NOT a retryable condition for the caller: the block has
    // already executed, so the state is ahead of the last accepted block and
    // building a second block on top of it would extend an uncertified state.
    // The daemon stops. Closing this properly needs an execution the VM can roll
    // back, which cevm's commit() does not offer today (LLM.md).
    std::optional<Decided> advance(int deadline_ms);

    // Lead a height: build the block, REGISTER it, publish it, then decide it.
    // The order is load-bearing and that is why it is one call rather than three
    // the caller sequences. Registering before publishing is what lets a
    // follower's vote — which can arrive before this node has finished its own
    // round — be counted at all; published first, every such vote named a block
    // this node had not submitted, and a validator broadcasts its ACCEPT exactly
    // once.
    std::optional<Decided> propose(
        const std::function<void(std::span<const std::uint8_t>)>& publish, int deadline_ms);

    // A block that arrived from a peer: parse it (which EXECUTES it and derives
    // this node's own root) and decide it. Same loop, different source of the
    // block — which is the only difference between proposing and following.
    std::optional<Decided> follow(std::span<const std::uint8_t> block_bytes, int deadline_ms);

    // Decide a block this caller already has. `advance` is build-then-decide and
    // `follow` is parse-then-decide; a proposer that must PUBLISH the block
    // between those two steps needs them apart, so the second half is public.
    // Whichever way the block was obtained, this is the only path to a
    // certificate.
    std::optional<Decided> decide(const std::shared_ptr<Block>&, int deadline_ms);

    VM&       vm() noexcept { return *vm_; }
    const VM& vm() const noexcept { return *vm_; }

    std::uint64_t height() const { return vm_->last_accepted_height(); }

private:
    // The signed position for a block. ONE definition, so a block proposed and
    // the same block followed produce the identical signed message — otherwise a
    // proposer and its followers would never agree on anything.
    lux::consensus::VotePosition position(const Block&) const;

    // Register the block, then run the rounds until it certifies. `decide` and
    // `propose` differ only in what happens between those two steps.
    std::optional<Decided> settle(const std::shared_ptr<Block>&, int deadline_ms,
                                  const std::function<void()>& after_submit);

    std::unique_ptr<VM> vm_;
    Node2Host&          host_;
    std::mutex&         guard_;
};

}  // namespace lux::node
