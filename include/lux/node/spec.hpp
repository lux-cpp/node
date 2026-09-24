// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// spec.hpp — what a network is, and the one call that runs a node on it.
//
// A network's daemon is this node run on that network's spec: its name, the
// network id its validators greet under, the chain id its EVM signs against,
// and the genesis that chain starts from. A brand's repository holds its specs
// and a main that calls run(); everything else — the mesh, consensus, the RPC,
// the EVM — is this node's, so there is one implementation for every network
// to match rather than one per brand.

#pragma once

#include <cstdint>
#include <span>
#include <string>

namespace lux::node {

struct Spec {
    std::string   name;      // what --network selects: "mainnet", "testnet", …
    std::string   client;    // what web3_clientVersion answers: "zooai/zood/v0.1.0"
    std::string   endpoint;  // the network's public API
    std::uint32_t network;   // the id validators greet each other under
    std::uint64_t chain;     // the id an EVM transaction is signed against
    std::string   genesis;   // the chain's genesis document, as JSON
    std::string   vm;        // the EVM plugin the chain runs in
};

// Run a node on the spec `--network NAME` selects, or on the first when the
// command line names none. Returns the process exit status.
int run(std::span<const Spec> specs, int argc, char** argv);

}  // namespace lux::node
