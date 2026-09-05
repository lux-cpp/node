// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco

#include "lux/node/network.hpp"

#include <algorithm>
#include <string_view>

namespace lux::node {
namespace {

// THE ownership table, and the one place a chain id becomes a name.
//
// A row is a NETWORK, not an environment: `ids` are the EVM chain ids that
// network runs under across mainnet, testnet, local and localnet, and for a
// sovereign L1 those are its primary network ids too. `chain` is what its EVM
// answers to; `rest` are the network's OTHER chains, which only Lux has —
// P and X are chains of the Lux primary network, and a sovereign L1 runs an EVM
// and nothing else.
struct Row {
    std::string_view              name;
    std::string_view              chain;
    std::vector<std::uint64_t>    ids;
    std::vector<std::string_view> rest;
};

const std::vector<Row>& table() {
    static const std::vector<Row> rows{
        // Lux devnet is 96367. The number 96370 is written down too, in
        // luxfi/constants, and no shipped config answers to it; the genesis
        // configs are the ones a chain is actually built from, so they win.
        {"lux",   "c",     {96369, 96368, 96367, 31337}, {"p", "x"}},
        {"hanzo", "hanzo", {36963, 36962, 36964},        {}},
        {"zoo",   "zoo",   {200200, 200201, 200202},     {}},
    };
    return rows;
}

}  // namespace

bool Network::owns(const std::string& alias) const {
    return std::find(owned.begin(), owned.end(), alias) != owned.end();
}

Network network_of(std::uint64_t chain_id) {
    const std::string self = std::to_string(chain_id);
    for (const Row& row : table()) {
        if (std::find(row.ids.begin(), row.ids.end(), chain_id) == row.ids.end()) continue;
        Network net;
        net.name   = std::string(row.name);
        net.served = {std::string(row.chain), self};
        net.owned  = net.served;
        for (const auto& other : row.rest) net.owned.emplace_back(other);
        return net;
    }
    // A chain id no row claims is still exactly one chain: it answers under its
    // own number and under nothing else. Falling through to Lux here would hand
    // an unknown chain the C-Chain's name — the bug this table exists to remove.
    return Network{{}, {self}, {self}};
}

}  // namespace lux::node
