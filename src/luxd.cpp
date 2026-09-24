// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// luxd — this node on a local Lux chain, 31337, the chain id luxfi/genesis
// calls LocalChainID. Its allocation is the first Anvil/Hardhat account, whose
// key every local Ethereum toolchain already holds, and the treasury signer:
//
//   secret  0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
//   address 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266

#include "local.hpp"
#include "lux/node/spec.hpp"

#include <array>

namespace {

const lux::node::Spec kLocal{
    .name     = "local",
    .client   = "lux-cpp/luxd/v0.1.0",
    .endpoint = "https://api.lux.network",
    .network  = 1337,
    .chain    = 31337,
    .genesis  = lux::node::kLocalGenesis,
    .vm = "/usr/local/libexec/lux/cevm",
};

const std::array kSpecs{kLocal};

}  // namespace

int main(int argc, char** argv) { return lux::node::run(kSpecs, argc, argv); }
