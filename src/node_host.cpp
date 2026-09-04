// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco

#include "lux/node/node_host.hpp"

namespace lux::node {

Node2Host::Node2Host(HostConfig cfg)
    : cfg_(std::move(cfg)),
      // The transport hands inbound and self-echoed votes to the Party. The sink is
      // only invoked during poll/pump — after node_ exists — so capturing a member
      // set just below is safe.
      tx_(std::make_unique<MeshVoteTransport>(
          [this](const lux::consensus::SignedVote& v) { deliver(v); })),
      mesh_(cfg_.index, *tx_),
      node_(std::make_unique<lux::consensus::Party>(
          cfg_.index, cfg_.sk, cfg_.pk, cfg_.validators,
          cfg_.wave, *tx_)) {
    // Seed the decided-height frontier from this node's OWN durable record before
    // it can sign anything. consensus::Party keeps the frontier in memory, so a
    // restart that skipped this could sign a second, conflicting block at a height
    // it had already decided. Doing it in the constructor is what makes that
    // impossible to forget — there is no window between existing and being seeded.
    node_->mark_finalized_through(cfg_.accepted);
}

Node2Host::~Node2Host() = default;

void Node2Host::deliver(const lux::consensus::SignedVote& v) {
    if (node_->onVote(v) != lux::consensus::VoteResult::RejectedNoSuchBlock) return;
    // The block is not registered here YET. The sender will not say this again,
    // so keep the vote rather than lose it — until the buffer is full, past which
    // dropping is the only bounded answer.
    if (early_.size() < kMaxEarlyVotes) early_.push_back(v);
}

void Node2Host::replay() {
    if (early_.empty()) return;
    // Anything still unknown after this belongs to a block this node is not
    // deciding, so the buffer is emptied rather than carried into the next
    // height.
    std::vector<lux::consensus::SignedVote> held;
    held.swap(early_);
    for (const auto& v : held) node_->onVote(v);
}

std::optional<lux::consensus::QuorumCert> Node2Host::accept(const lux::consensus::VotePosition& pos) {
    auto c = node_->cert(pos.block_id);
    if (!c || !node_->verifyCert(*c)) return std::nullopt;
    node_->mark_finalized_through(pos.height);
    return c;
}

}  // namespace lux::node
