// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// validators.hpp — the commitment a vote binds its validator set with.
//
// `VotePosition::validator_set_root` exists so a certificate cannot be
// re-presented under a different set: the root is part of the signed message,
// so a cross-epoch stake change invalidates the signature rather than silently
// re-weighting an old cert. Until now this node left it empty, which is a
// consistent answer but not the network's answer — and a validator whose signed
// message differs from luxd's has its votes dropped, not disputed.
//
// The encoding is Go's `hashValidatorSet` (luxfi/node chains/quorum.go), and it
// is copied here field for field because "compatible" is not a property one can
// approximate:
//
//     empty set                      → the all-zero id
//     otherwise SHA-256 over, per validator, sorted by RAW node id ascending:
//         node id      20 bytes
//         weight        8 bytes, big-endian
//         len(pubkey)   8 bytes, big-endian
//         pubkey        len bytes, UNCOMPRESSED (96 for BLS12-381 G1)
//
// Two details are the ones that actually bite. The key is UNCOMPRESSED — the
// 48-byte compressed form is what the proof of possession signs, and using it
// here produces a different root that verifies against nothing. And the weight
// is the set's EFFECTIVE weight as the P-chain computed it, not the weight
// genesis declared: allocations add stake, so a validator declared at 1e12 can
// be in force at 3.75e9, and hashing the declared number commits to a set that
// does not exist.

#pragma once

#include "lux/consensus/quorum_cert_engine.hpp"  // Id

#include <array>
#include <cstdint>
#include <vector>

namespace lux::node {

using lux::consensus::Id;

// One validator, as the set root commits to it. This is deliberately NOT
// consensus::Validator: that type carries what the GATE needs (a 48-byte
// compressed key it verifies signatures with), and this carries what the
// COMMITMENT needs (a node id and the uncompressed key). Same validators, two
// different questions, and conflating them is how the compressed key ends up in
// the root.
struct SetMember {
    std::array<std::uint8_t, 20> node_id{};
    std::uint64_t                weight = 0;   // Go's GetValidatorOutput.Light
    std::vector<std::uint8_t>    pubkey;       // UNCOMPRESSED, 96 bytes for BLS G1
};

// The canonical commitment to `members`. Sorts internally, so a caller cannot
// get the order wrong; an empty set commits to the all-zero id, which is the
// explicit "unbound" answer Go gives and not an error.
[[nodiscard]] Id validator_set_root(std::vector<SetMember> members);

}  // namespace lux::node
