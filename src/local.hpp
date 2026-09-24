// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// local.hpp — the local chain's genesis (31337, luxfi/genesis LocalChainID),
// one definition for luxd and for the tool that builds its test export.

#pragma once

namespace lux::node {

inline constexpr const char* kLocalGenesis = R"({
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
})";

}  // namespace lux::node
