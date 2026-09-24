// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// windower.hpp — who may propose at a height and a slot: Go's proposer windower.
//
// `luxfi/node vms/proposervm/proposer/windower.go` names ONE validator per
// (height, slot) — `expectedProposer` (windower.go:306): a stake-weighted draw
// over the validators sorted by node id (windower.go:271-304), from a 64-bit
// Mersenne Twister (gonum `prng.MT19937_64`) seeded with
// `chainSource ^ height ^ bits.Reverse64(slot)` (windower.go:317), where
// `chainSource` is the chain id's first eight bytes read little-endian
// (windower.go:153). The draw is `luxfi/container/sampler`'s: a value in
// `[0, total weight)` from `Uint64Inclusive`, located in a weighted heap. Every
// step is ported, byte for byte, from lux-rs/node src/proposer.rs:79-236, which
// holds it to the vectors windower_test.go holds Go to; windower_test.cpp holds
// this one to the same vectors.
//
// A PROPOSAL IS SIGNED, in the shape Go's proposervm signs a block under strict
// PQ (`BuildMLDSA`, proposervm/block/build.go:69): ML-DSA-65 over a header
// binding the chain, the parent and the body (`BuildHeader(chainID, parentID,
// blockID)`, build.go:112). The context is this node's own, never Go's
// `lux-proposervm-block-v1`, so a signature over these bytes can never be read as
// a proposervm block. The body is SHA-256 over the validator-set root, parent,
// height, slot, the scheme byte and ML-DSA key Go puts in its certificate slot
// (block.go:42), and the block — lux-rs/node src/proposer.rs:45-77, the same
// bytes.

#pragma once

#include "lux/node/committee.hpp"  // Node, Id

#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace lux::node {

// This node's proposal context (FIPS 204 ctx): a proposer's signature can never
// be read as any other signature a validator makes. proposer.rs:47.
inline constexpr std::string_view kProposalContext = "lux-node-proposal-v1";

// Go's scheme byte for an ML-DSA-65 proposer identity (`ids.NodeIDSchemeMLDSA65`).
inline constexpr std::uint8_t kMLDSA65Scheme = 0x42;

// The 96 bytes a proposer signs: chain ‖ parent ‖ SHA-256(set ‖ parent ‖
// height ‖ slot ‖ scheme ‖ identity ‖ block), integers big-endian.
[[nodiscard]] std::array<std::uint8_t, 96> proposal_header(
    const Id& chain, const Id& set, const Id& parent, std::uint64_t height, std::uint64_t slot,
    std::span<const std::uint8_t> identity, std::span<const std::uint8_t> block);

// One validator set's proposer schedule on one chain.
class Windower {
public:
    // The schedule of `validators` (node id, weight) on `chain`. Throws
    // std::invalid_argument for an empty set, a set whose weights sum to zero,
    // and one whose weights overflow: Go answers the first two with
    // ErrAnyoneCanPropose, and a chain where anyone can propose is the chain this
    // schedule exists to prevent.
    Windower(const Id& chain, std::vector<std::pair<Node, std::uint64_t>> validators);

    // ExpectedProposer(height, slot): the one validator whose window is `slot`
    // at `height`.
    [[nodiscard]] Node expected(std::uint64_t height, std::uint64_t slot) const;

private:
    struct Entry {
        std::uint64_t weight;
        std::uint64_t subtree;
        std::size_t   index;
    };
    std::uint64_t      source_ = 0;
    std::vector<Node>  ids_;   // sorted by node id — the order a sample indexes
    std::vector<Entry> heap_;  // heaviest first, index breaking ties
};

}  // namespace lux::node
