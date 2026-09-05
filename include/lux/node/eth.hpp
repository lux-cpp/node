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

// Mount `admin_importChain` — the RPC door onto import_chain_data, and the
// second of the two the node has. It is a door and nothing else: it reads a
// path out of the params, calls the same function `--import-chain-data` calls,
// and renders what came back. Go's is the same nine lines (admin_api.go:84).
//
// The lock is already right and is worth saying why: `Rpc` holds THE chain lock
// for the whole of every method call, which is what Go spells `vmLock.Lock()`
// at the top of ImportChain — so a read that arrives while consensus is
// advancing a height waits for it, and the reader never sees a half-moved tip.
void serve_admin(Rpc& rpc, evm::Chain& chain);

}  // namespace lux::node
