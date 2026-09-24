// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// windower_test.cpp — the proposer schedule is Go's, held to the vectors
// luxfi/node vms/proposervm/proposer/windower_test.go holds Go to, and to the
// ones lux-rs/node src/proposer.rs holds Rust to. A windower that agreed only
// with itself would name a proposer no other implementation expects.

#include "lux/node/windower.hpp"

#include <algorithm>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>

using namespace lux::node;

namespace {

int g_fail = 0;
void check(bool ok, const std::string& what) {
    std::printf("  %s  %s\n", ok ? "ok  " : "FAIL", what.c_str());
    if (!ok) ++g_fail;
}

// ids.BuildTestNodeID([]byte{i + 1}): the id's first byte, zeros after.
std::vector<Node> validators(std::uint8_t n) {
    std::vector<Node> out;
    for (std::uint8_t i = 0; i < n; ++i) {
        Node id{};
        id[0] = std::uint8_t(i + 1);
        out.push_back(id);
    }
    return out;
}

// fixedChainID = ids.ID{0, 2}.
Id fixed() {
    Id id{};
    id[1] = 2;
    return id;
}

Windower windower(const std::vector<Node>& ids) {
    std::vector<std::pair<Node, std::uint64_t>> set;
    for (const auto& id : ids) set.emplace_back(id, 1);
    return Windower(fixed(), set);
}

}  // namespace

int main() {
    std::printf("=============== node — the proposer windower is Go's ===============\n");

    {
        // TestExpectedProposerChangeBySlot, windower_test.go:257.
        const auto ids = validators(10);
        const auto w   = windower(ids);
        const int  go[] = {7, 9, 7, 0, 4, 8, 1, 8, 9, 9, 7, 3, 8, 6, 5, 4, 2, 9, 1, 4, 1, 4, 8, 3};
        bool       all  = true;
        for (std::uint64_t slot = 0; slot < 24; ++slot)
            if (w.expected(1, slot) != ids[std::size_t(go[slot])]) {
                all = false;
                std::printf("    slot %llu differs\n", static_cast<unsigned long long>(slot));
            }
        check(all, "height 1, slots 0..23: the proposer Go names at each");
        check(w.expected(1, 720) == ids[3], "slot 720 (MaxLookAheadSlots) is Go's");
        check(w.expected(1, 721) == ids[4], "slot 721 is Go's");
    }
    {
        // TestExpectedProposerChangeByHeight, windower_test.go:197.
        const auto ids = validators(10);
        const auto w   = windower(ids);
        check(w.expected(1, 0) == ids[7] && w.expected(2, 0) == ids[1], "slot 0 at heights 1 and 2 is Go's");
    }
    {
        // The order the set is written in does not move a single window.
        const auto ids = validators(5);
        const auto w   = windower(ids);
        std::vector<std::pair<Node, std::uint64_t>> shuffled{
            {ids[4], 1}, {ids[1], 1}, {ids[3], 1}, {ids[0], 1}, {ids[2], 1}};
        const Windower v(fixed(), shuffled);
        bool           same = true;
        for (std::uint64_t h = 0; h < 50; ++h)
            for (std::uint64_t s = 0; s < 20; ++s) same = same && w.expected(h, s) == v.expected(h, s);
        check(same, "one set in any order is one schedule");
    }
    {
        // Every validator gets windows, and weight buys more.
        const auto ids = validators(4);
        const Windower w(fixed(), {{ids[0], 1}, {ids[1], 1}, {ids[2], 1}, {ids[3], 5}});
        std::size_t count[4] = {};
        for (std::uint64_t s = 0; s < 8000; ++s)
            for (std::size_t i = 0; i < 4; ++i)
                if (w.expected(7, s) == ids[i]) ++count[i];
        check(count[0] > 0 && count[1] > 0 && count[2] > 0 && count[3] > 0, "every validator has windows");
        check(count[3] > 3 * count[0], "five times the weight, more than three times the windows");
    }
    {
        // A proposal header binds every field it is built from.
        const Id    chain{1}, set{6}, parent{2};
        const std::vector<std::uint8_t> key(8, 5), block{'b', 'l', 'o', 'c', 'k'};
        const auto base = proposal_header(chain, set, parent, 3, 4, key, block);
        check(std::equal(chain.begin(), chain.end(), base.begin()) &&
                  std::equal(parent.begin(), parent.end(), base.begin() + 32),
              "the header opens with the chain and the parent");
        const Id    nine{9};
        const std::vector<std::uint8_t> other_key(8, 9), other_block{'o', 't', 'h', 'e', 'r'};
        bool moved = proposal_header(nine, set, parent, 3, 4, key, block) != base &&
                     proposal_header(chain, nine, parent, 3, 4, key, block) != base &&
                     proposal_header(chain, set, nine, 3, 4, key, block) != base &&
                     proposal_header(chain, set, parent, 9, 4, key, block) != base &&
                     proposal_header(chain, set, parent, 3, 9, key, block) != base &&
                     proposal_header(chain, set, parent, 3, 4, other_key, block) != base &&
                     proposal_header(chain, set, parent, 3, 4, key, other_block) != base;
        check(moved, "each of chain, set, parent, height, slot, key and block moves it");
    }
    {
        bool refused = false;
        try { (void)Windower(fixed(), {}); } catch (const std::invalid_argument&) { refused = true; }
        check(refused, "an empty set has no schedule");
        refused = false;
        try { (void)Windower(fixed(), {{Node{1}, 0}}); } catch (const std::invalid_argument&) { refused = true; }
        check(refused, "a weightless set has no schedule");
        refused = false;
        try {
            (void)Windower(fixed(), {{Node{1}, ~std::uint64_t(0)}, {Node{2}, 1}});
        } catch (const std::invalid_argument&) {
            refused = true;
        }
        check(refused, "weights that overflow have no schedule");
    }

    std::printf("--------------------------------------------------------------------\n");
    if (g_fail) { std::printf("==== node WINDOWER: FAIL (%d) ====\n", g_fail); return 1; }
    std::printf("==== node WINDOWER: PASS — Go's proposer, window for window ====\n");
    return 0;
}
