// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco

#include "lux/node/windower.hpp"

#include <sha256/cpp/sha256.hpp>

#include <algorithm>
#include <cstddef>
#include <limits>
#include <stdexcept>

namespace lux::node {

namespace {

void put_be64(std::vector<std::uint8_t>& out, std::uint64_t v) {
    for (int s = 56; s >= 0; s -= 8) out.push_back(static_cast<std::uint8_t>(v >> s));
}

std::uint64_t reverse64(std::uint64_t v) noexcept {
    std::uint64_t r = 0;
    for (int i = 0; i < 64; ++i) {
        r = (r << 1) | (v & 1);
        v >>= 1;
    }
    return r;
}

// MT19937-64 — Matsumoto and Nishimura's reference mt19937-64.c, as gonum
// states it (prng.MT19937_64). proposer.rs:79-128.
class Twister {
public:
    explicit Twister(std::uint64_t seed) {
        mt_[0] = seed;
        for (std::size_t i = 1; i < kN; ++i)
            mt_[i] = 6364136223846793005ULL * (mt_[i - 1] ^ (mt_[i - 1] >> 62)) + i;
        at_ = kN;
    }

    std::uint64_t next() {
        const auto mag = [](std::uint64_t x) { return (x & 1) ? kMatrix : 0; };
        if (at_ >= kN) {
            for (std::size_t i = 0; i < kN - kM; ++i) {
                const std::uint64_t x = (mt_[i] & kUpper) | (mt_[i + 1] & kLower);
                mt_[i] = mt_[i + kM] ^ (x >> 1) ^ mag(x);
            }
            for (std::size_t i = kN - kM; i < kN - 1; ++i) {
                const std::uint64_t x = (mt_[i] & kUpper) | (mt_[i + 1] & kLower);
                mt_[i] = mt_[i - (kN - kM)] ^ (x >> 1) ^ mag(x);
            }
            const std::uint64_t x = (mt_[kN - 1] & kUpper) | (mt_[0] & kLower);
            mt_[kN - 1] = mt_[kM - 1] ^ (x >> 1) ^ mag(x);
            at_ = 0;
        }
        std::uint64_t x = mt_[at_++];
        x ^= (x >> 29) & 0x5555555555555555ULL;
        x ^= (x << 17) & 0x71D67FFFEDA60000ULL;
        x ^= (x << 37) & 0xFFF7EEE000000000ULL;
        return x ^ (x >> 43);
    }

    // sampler.rng.Uint64Inclusive: a value in [0, n]. Every branch is Go's,
    // rejection loops included, because the result is chain state.
    // proposer.rs:130-152.
    std::uint64_t inclusive(std::uint64_t n) {
        if ((n & (n + 1)) == 0) return next() & n;
        constexpr std::uint64_t kMaxI64 = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
        if (n > kMaxI64) {
            for (;;) {
                const std::uint64_t v = next();
                if (v <= n) return v;
            }
        }
        const std::uint64_t most = (1ULL << 63) - 1 - (1ULL << 63) % (n + 1);
        for (;;) {
            const std::uint64_t v = next() & kMaxI64;
            if (v <= most) return v % (n + 1);
        }
    }

    static constexpr std::size_t   kN      = 312;
    static constexpr std::size_t   kM      = 156;
    static constexpr std::uint64_t kMatrix = 0xB5026F5AA96619E9ULL;
    static constexpr std::uint64_t kUpper  = 0xFFFFFFFF80000000ULL;
    static constexpr std::uint64_t kLower  = 0x7FFFFFFFULL;

private:
    std::array<std::uint64_t, kN> mt_{};
    std::size_t                   at_ = kN;
};

}  // namespace

std::array<std::uint8_t, 96> proposal_header(const Id& chain, const Id& set, const Id& parent,
                                              std::uint64_t height, std::uint64_t slot,
                                              std::span<const std::uint8_t> identity,
                                              std::span<const std::uint8_t> block) {
    std::vector<std::uint8_t> body;
    body.reserve(32 + 32 + 8 + 8 + 1 + identity.size() + block.size());
    body.insert(body.end(), set.begin(), set.end());
    body.insert(body.end(), parent.begin(), parent.end());
    put_be64(body, height);
    put_be64(body, slot);
    body.push_back(kMLDSA65Scheme);
    body.insert(body.end(), identity.begin(), identity.end());
    body.insert(body.end(), block.begin(), block.end());

    std::array<std::uint8_t, 96> h{};
    std::copy(chain.begin(), chain.end(), h.begin());
    std::copy(parent.begin(), parent.end(), h.begin() + 32);
    cevm::crypto::sha256(reinterpret_cast<std::byte*>(h.data() + 64),
                         reinterpret_cast<const std::byte*>(body.data()), body.size());
    return h;
}

Windower::Windower(const Id& chain, std::vector<std::pair<Node, std::uint64_t>> validators) {
    std::sort(validators.begin(), validators.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });
    heap_.reserve(validators.size());
    for (std::size_t i = 0; i < validators.size(); ++i) {
        ids_.push_back(validators[i].first);
        heap_.push_back(Entry{validators[i].second, validators[i].second, i});
    }
    // weightedHeap: heaviest first, the index breaking ties, then each node
    // carries the weight of its subtree. proposer.rs:163-172.
    std::sort(heap_.begin(), heap_.end(), [](const Entry& a, const Entry& b) {
        return a.weight != b.weight ? a.weight > b.weight : a.index < b.index;
    });
    for (std::size_t i = heap_.size(); i-- > 1;) {
        const std::size_t parent = (i - 1) >> 1;
        if (heap_[parent].subtree > std::numeric_limits<std::uint64_t>::max() - heap_[i].subtree)
            throw std::invalid_argument("windower: the validators' weights overflow");
        heap_[parent].subtree += heap_[i].subtree;
    }
    if (heap_.empty() || heap_.front().subtree == 0)
        throw std::invalid_argument("windower: a proposer schedule needs a validator with weight");
    for (int i = 0; i < 8; ++i) source_ |= std::uint64_t(chain[std::size_t(i)]) << (8 * i);
}

Node Windower::expected(std::uint64_t height, std::uint64_t slot) const {
    Twister       rng(source_ ^ height ^ reverse64(slot));
    std::uint64_t value = rng.inclusive(heap_.front().subtree - 1);
    // weightedHeap.Sample. proposer.rs:178-197.
    std::size_t i = 0;
    for (;;) {
        const Entry& e = heap_[i];
        if (value < e.weight) return ids_[e.index];
        value -= e.weight;
        i = i * 2 + 1;
        const std::uint64_t left = heap_[i].subtree;
        if (left <= value) {
            value -= left;
            ++i;
        }
    }
}

}  // namespace lux::node
