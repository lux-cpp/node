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
// That is a DELIBERATE DIVERGENCE, and it is not a free one — it decides who
// this node can form a quorum WITH, so it is a named choice rather than a
// constant. See `Binding`.

#pragma once

#include "lux/node/node_host.hpp"
#include "lux/node/vm.hpp"

#include <functional>
#include <memory>
#include <mutex>
#include <optional>

namespace lux::node {

// WHOSE MESSAGE THIS NODE SIGNS.
//
// The vote's execution axes can be filled two ways, and the two are mutually
// exclusive: a signed message either commits to the root this node computed or
// it does not, and validators that disagree about which do not form a quorum —
// their signatures simply fail to verify against each other's message.
//
//   Executed — bind execution_state_root to what THIS node's EVM produced.
//     Stronger, and the reason is that divergent execution cannot hide: two
//     nodes whose EVMs disagree sign different messages and stall the height
//     instead of both signing a name they each mean differently.
//
//   Transport — leave the execution axes empty, which is what luxd signs.
//     Go's proposervm returns ids.Empty for ExecutionStateRoot, and a Go voter
//     does not execute the block it votes on. Matching that is the ONLY way a
//     C++ node's votes verify inside a live Go network; binding the root there
//     produces a message luxd drops rather than disputes.
//
// Both are correct; which one is right depends on the network. A pure C++
// cluster takes Executed. Joining luxd takes Transport, until Go binds the axis
// too — at which point this collapses back to one answer, which is where it
// should end up.
enum class Binding {
    Executed,   // bind the root this node computed — a C++-only cluster
    Transport,  // leave it empty, as luxd does — a mixed cluster
};

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
    // `binding` decides whose signed message this node produces; see Binding.
    // `set_root` is the commitment to the validator set the vote is cast under,
    // which every node in the quorum must compute identically.
    Engine(std::unique_ptr<VM> vm, Node2Host& host, std::mutex& guard,
           Binding binding = Binding::Executed, Id set_root = {});

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

    // MAY THIS NODE PUT ITS SIGNATURE ON A HEIGHT AT ALL.
    //
    // False when the chain's tip sits above the highest height this node
    // decided — the state a chain is left in by reading an export, which moves
    // the tip and produces no certificate under it. Everything below such a tip
    // is history this node took on someone else's word, so a vote cast from it
    // would put this validator's name on an ancestry it never verified, and a
    // block built on it would extend one. Refusing is the whole point: an
    // implementation that imports and then proposes is worse than one that
    // cannot import at all.
    //
    // Go reaches the same refusal from the other end — proposervm sees a
    // missing outer anchor, enters backfill, and gates BuildBlock off until the
    // outer index is rebuilt from certified peer state (vms/proposervm/vm.go).
    // Same rule, said where this node produces a signature rather than where it
    // wraps a block.
    bool may_sign() const { return vm_->frontier() >= vm_->last_accepted_height(); }

private:
    // The signed position for a block. ONE definition, so a block proposed and
    // the same block followed produce the identical signed message — otherwise a
    // proposer and its followers would never agree on anything.
    lux::consensus::VotePosition position(const Block&) const;

    // Register the block, then run the rounds until it certifies. `decide` and
    // `propose` differ only in what happens between those two steps.
    //
    // A registered block that does NOT certify is rejected before this returns.
    // It is the only honest reading: settle is the whole life of a block here,
    // so a block it gives up on is a block that will never be accepted, and its
    // transactions belong back in the pool rather than in a block nobody has.
    std::optional<Decided> settle(const std::shared_ptr<Block>&, int deadline_ms,
                                  const std::function<void()>& after_submit);

    std::unique_ptr<VM> vm_;
    Node2Host&          host_;
    std::mutex&         guard_;
    Binding             binding_;
    Id                  set_root_;
};

}  // namespace lux::node
