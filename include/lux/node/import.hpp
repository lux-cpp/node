// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// import.hpp — read a chain back out of the C-chain's EXTERNAL format.
//
// The C-chain speaks two encodings and this reads the outward-facing one. ZAP
// is the serialization everything in this stack uses; RLP is what the C-chain
// hands to Ethereum, and an export of a chain's history — the file `geth
// import` and luxd's `--import-chain-data` both take — is a bare concatenation
// of RLP-encoded blocks with no envelope, no index and no length prefix. Read
// it, and you have a chain's past in the only form the outside world has it.
//
// WHAT IS PROVEN HERE, AND WHAT IS ONLY CARRIED. Every hash this reader
// compares against is one it computed:
//
//   · a block's id is keccak(rlp(header)) over the header's own bytes;
//   · block N's parentHash must equal the id computed for block N-1, walked
//     over every block in the file rather than sampled — a break is a refusal;
//   · the transactionsRoot is rebuilt as a Merkle-Patricia trie over the body's
//     transactions and must equal the header's, which is what binds a body to
//     the header that names it;
//   · the ommersHash is keccak of the uncle list's own RLP;
//   · every transaction is decoded and its sender RECOVERED from its signature,
//     which also refuses an export belonging to another chain: a transaction
//     binds its chain id, so lux-testnet's blocks do not decode into a node
//     configured for lux-mainnet.
//
// The stateRoot is the one thing NOT proven, and saying so is the point. An
// export carries blocks, not state; deriving these roots would mean executing
// every transaction from the genesis ALLOCATION, which an export does not
// contain. So the roots are read from the headers as claims and the node is
// left knowing a tip whose state it did not compute — one of the two reasons
// `Chain::frontier()` stays below the tip after a read, the other being that
// nothing certified any of it.
//
// IDEMPOTENT. A node already at or above the file's tip skips every block and
// reports zero ingested, which is a SUCCESS: the flag stays set in a pod spec,
// so every restart re-enters this path and a re-read must not be a failure. Go
// reaches the same behaviour by returning a "nothing to import" error and
// classifying it back into success at the call site (isNothingToImportError);
// this returns the counts and lets the caller read them.

#pragma once

#include "lux/node/evm.hpp"

#include <cstdint>
#include <string>

namespace lux::node {

// What reading an export produced.
struct Import {
    std::uint64_t blocks    = 0;  // ingested here
    std::uint64_t skipped   = 0;  // already held, at or below the tip on entry
    std::uint64_t txs       = 0;  // transactions decoded, senders recovered
    Id            genesis{};      // keccak(rlp(header)) of the file's block 0
    Id            tip{};          // …and of the highest block ingested
    Id            root{};         // that block's stateRoot — carried, not derived
    std::uint64_t height    = 0;
    std::uint64_t timestamp = 0;
};

// Read the RLP block export at `path` into `chain`.
//
// Throws std::runtime_error on anything that does not hold: a file that will
// not open, a malformed or truncated encoding, a header the wrong shape, a
// recomputed root that disagrees with the header, a parent that does not name
// the block before it, a height that skips, or a transaction that does not
// decode and recover on this chain. A refusal names the block it stopped at.
Import import_chain_data(evm::Chain& chain, const std::string& path);

}  // namespace lux::node
