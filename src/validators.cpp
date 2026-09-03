// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco

#include "lux/node/validators.hpp"

#include <sha256/cpp/sha256.hpp>

#include <algorithm>
#include <cstddef>

namespace lux::node {
namespace {

void put_be64(std::vector<std::uint8_t>& out, std::uint64_t v) {
    for (int i = 7; i >= 0; --i)
        out.push_back(static_cast<std::uint8_t>((v >> (i * 8)) & 0xff));
}

}  // namespace

Id validator_set_root(std::vector<SetMember> members) {
    // An empty set is "unbound", not an error, and it commits to the zero id.
    // Hashing nothing would give sha256("") instead, which is a perfectly good
    // hash of the wrong thing.
    if (members.empty()) return lux::consensus::kEmptyId;

    std::sort(members.begin(), members.end(),
              [](const SetMember& a, const SetMember& b) { return a.node_id < b.node_id; });

    std::vector<std::uint8_t> preimage;
    preimage.reserve(members.size() * (20 + 8 + 8 + 96));
    for (const auto& m : members) {
        preimage.insert(preimage.end(), m.node_id.begin(), m.node_id.end());
        put_be64(preimage, m.weight);
        put_be64(preimage, m.pubkey.size());
        preimage.insert(preimage.end(), m.pubkey.begin(), m.pubkey.end());
    }

    Id root{};
    cevm::crypto::sha256(reinterpret_cast<std::byte*>(root.data()),
                         reinterpret_cast<const std::byte*>(preimage.data()),
                         preimage.size());
    return root;
}

}  // namespace lux::node
