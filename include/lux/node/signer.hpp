// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// signer.hpp — what this validator holds: the name it is known by, and the key
// it votes with.
//
// Two keys, two jobs, and they are not interchangeable:
//
//   identity   an ML-DSA-65 keypair (FIPS 204). The public half is what a
//              committee line NAMES this validator by, and the node id is what
//              that key derives ON A CHAIN — so the name and the key are the
//              same fact, and the same key is a different validator on every
//              network rather than a bearer credential on all of them.
//   consensus  a BLS12-381 secret. What a vote is signed with, and what the
//              proof of possession in a committee line proves this node holds.
//
// Both are made once, on first use, from the system's randomness, and kept at
// 0600. Deriving either from anything reproducible — an index, a seed shared
// across a cluster — would be a signing key someone else can compute, which is
// one validator wearing every hat rather than a committee.
//
// A daemon publishes the public halves with `publish()` and hands the line to
// whoever assembles the committee file. Nothing secret is in it, which is why
// it can be pasted into a text file and mailed around.

#pragma once

#include "lux/consensus/quorum_cert_engine.hpp"  // PubKey
#include "lux/node/committee.hpp"                // Node, and the naming rule

#include <array>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace lux::node {

class Signer {
public:
    // Load the keys in `dir`, making either that is missing. Throws
    // std::runtime_error at the boundary: a validator that cannot reach its own
    // key does not start with a fresh one silently.
    [[nodiscard]] static Signer open(const std::filesystem::path& dir);

    // The name this validator is known by on `chain`.
    [[nodiscard]] Node node(const std::array<std::uint8_t, 32>& chain) const;

    [[nodiscard]] const std::array<std::uint8_t, 32>& secret() const noexcept { return secret_; }
    [[nodiscard]] const lux::consensus::PubKey&       key() const noexcept { return key_; }

    // The line this validator publishes so others can put it in a committee of
    // `chain`. The proof of possession is over this validator's OWN name on that
    // chain, so a line published for one network is not a line on another: the
    // proof there is over a name nobody derives.
    [[nodiscard]] std::string publish(const std::array<std::uint8_t, 32>& chain) const;

private:
    std::vector<std::uint8_t>    identity_;  // ML-DSA-65 public key
    std::vector<std::uint8_t>    signer_;    // ML-DSA-65 secret key
    std::array<std::uint8_t, 32> secret_{};  // BLS secret
    lux::consensus::PubKey       key_{};     // BLS public, compressed
};

}  // namespace lux::node
