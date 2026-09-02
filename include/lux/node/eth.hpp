// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// eth.hpp — the C-Chain's JSON-RPC methods, mounted on an Rpc.
//
// Kept apart from both sides on purpose: `Rpc` knows HTTP and JSON and no
// chain; `evm::Chain` knows the EVM and no JSON. This is the one place the two
// meet, so P and X mount their surfaces the same way without either of them
// learning about the other.
//
// Every answer is read out of the live chain — the same StateDB execution
// writes and the same accepted height the quorum certificates advanced. There
// is no cache to go stale and no fixture to go wrong.

#pragma once

#include "lux/node/evm.hpp"
#include "lux/node/rpc.hpp"

#include <string>

namespace lux::node {

// Mount the eth / web3 / net methods for `chain` at `/v1/chain/<alias>/rpc`,
// and make that path answer a bare `POST /` as well (which is what luxd does).
// `client` is what web3_clientVersion reports.
void serve_eth(Rpc& rpc, evm::Chain& chain, const std::string& client);

}  // namespace lux::node
