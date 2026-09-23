// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// network.hpp — which chains a node is allowed to answer for.
//
// A node knows its own network, and a network OWNS a set of chain aliases. The
// node serves exactly those and refuses every other, so `/v1/chain/c` is
// answered by a Lux node and is a 404 on a Zoo one: C-Chain is the Lux primary
// network's EVM and no other network runs it. Without an owner an alias is just
// a word the caller chose, every node answers to every name, and a Zoo node
// serves `c` with Zoo's chain id inside it — which is exactly what it did.
//
// THE NETWORK COMES FROM THE CHAIN ID, never from the name of the binary. A
// sovereign L1's primary networkID IS its EVM chain id, so the id a node was
// started with is the whole of its identity; argv[0] is a guess that can
// disagree with it, and a guess is not an identity.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace lux::node {

// A network and the chain aliases it owns.
struct Network {
    // The network itself — "lux", "hanzo", "zoo". Empty when no row claims this
    // chain id, which is a chain WITHOUT a network rather than a default one.
    std::string name;

    // The aliases this node's own chain answers to: its canonical name first,
    // then its chain id in decimal. They name one chain, so one method table is
    // registered under each of them.
    std::vector<std::string> served;

    // Every alias the network owns: `served`, plus the network's other chains
    // (Lux's P and X). A path naming anything outside this set is not this
    // node's to answer — archive configured or not.
    std::vector<std::string> owned;

    bool owns(const std::string& alias) const;
};

// The network a chain id belongs to.
Network network_of(std::uint64_t chain_id);

}  // namespace lux::node
