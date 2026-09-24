// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// luxd — this node on a local Lux chain, 31337, the chain id luxfi/genesis
// calls LocalChainID. Its allocation is the first Anvil/Hardhat account, whose
// key every local Ethereum toolchain already holds, and the treasury signer:
//
//   secret  0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
//   address 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266

#include "lux/node/spec.hpp"

#include <array>

namespace {

const lux::node::Spec kLocal{
    .name     = "local",
    .client   = "lux-cpp/luxd/v0.1.0",
    .endpoint = "https://api.lux.network",
    .network  = 1337,
    .chain    = 31337,
    .genesis  = R"({
  "config": {
    "chainId": 31337,
    "homesteadBlock": 0, "eip150Block": 0, "eip155Block": 0, "eip158Block": 0,
    "byzantiumBlock": 0, "constantinopleBlock": 0, "petersburgBlock": 0,
    "istanbulBlock": 0, "muirGlacierBlock": 0, "berlinBlock": 0, "londonBlock": 0,
    "shanghaiTime": 0, "cancunTime": 0
  },
  "nonce": "0x0",
  "timestamp": "0x0",
  "extraData": "0x",
  "gasLimit": "0x1c9c380",
  "difficulty": "0x0",
  "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "coinbase": "0x0000000000000000000000000000000000000000",
  "baseFeePerGas": "0x5d21dba00",
  "alloc": {
    "f39fd6e51aad88f6f4ce6ab8827279cfffb92266": {"balance": "0x21e19e0c9bab2400000"},
    "9011e888251ab053b7bd1cdb598db4f9ded94714": {"balance": "0x21e19e0c9bab2400000"}
  }
})",
    .vm = "/usr/local/libexec/lux/cevm",
};

const std::array kSpecs{kLocal};

}  // namespace

int main(int argc, char** argv) { return lux::node::run(kSpecs, argc, argv); }
