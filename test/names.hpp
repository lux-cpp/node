// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// names.hpp — the identities a test cluster greets with.
//
// A mesh proves who is on the other end of every link (LP-10602), so a test
// that builds hosts has to give them something to prove. `Names` makes N
// ML-DSA-65 identities once and answers the seat question the way a committee
// does: by looking the PROVEN name up in the list it was built from.
//
// It lives in one header because four tests need it and four copies of it would
// be four chances to disagree about what a seat is.

#pragma once

#include "lux/node/mesh.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

namespace lux::node::test {

class Names {
public:
    explicit Names(std::uint32_t n) {
        ids_.reserve(n);
        for (std::uint32_t i = 0; i < n; ++i) ids_.push_back(pq::Identity::make());
    }

    // The greeting for the validator at `seat`. Borrowed from this object, so it
    // must outlive the hosts that hold it — which in a test it does.
    [[nodiscard]] Link link(std::uint32_t seat) const {
        Link l;
        l.me    = ids_[seat];
        l.chain = chain_;
        l.seat  = [this](const std::array<std::uint8_t, 20>& who) -> std::optional<std::uint32_t> {
            for (std::uint32_t i = 0; i < ids_.size(); ++i)
                if (ids_[i].node_id() == who) return i;
            return std::nullopt;
        };
        return l;
    }

    // A greeting for somebody who is in no committee: a real identity, and no
    // seat anywhere.
    [[nodiscard]] Link stranger() const {
        Link l = link(0);
        l.me   = pq::Identity::make();
        return l;
    }

    [[nodiscard]] std::array<std::uint8_t, 20> name(std::uint32_t seat) const {
        return ids_[seat].node_id();
    }
    [[nodiscard]] const std::array<std::uint8_t, 32>& chain() const noexcept { return chain_; }

private:
    std::array<std::uint8_t, 32> chain_{};
    std::vector<pq::Identity>    ids_;
};

}  // namespace lux::node::test
