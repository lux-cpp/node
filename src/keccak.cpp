// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco

#include "lux/node/keccak.hpp"

#include <algorithm>
#include <cstring>

namespace lux::node::keccak {

namespace {

inline std::uint64_t rotl64(std::uint64_t x, int n) noexcept {
    return (x << n) | (x >> (64 - n));
}

// Standard compact Keccak-f[1600] — the widely-reproduced reference
// structure (round constants + the rotation-offset/lane-permutation tables
// below are the canonical Keccak values; this is not an invented variant).
void keccak_f1600(std::uint64_t st[25]) noexcept {
    static constexpr std::uint64_t kRC[24] = {
        0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
        0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
        0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
        0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
        0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
        0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
    };
    static constexpr int kRotc[24] = {
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
    };
    static constexpr int kPiLn[24] = {
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
    };

    for (int round = 0; round < 24; ++round) {
        // Theta
        std::uint64_t bc[5];
        for (int i = 0; i < 5; ++i) bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        for (int i = 0; i < 5; ++i) {
            std::uint64_t t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5) st[j + i] ^= t;
        }
        // Rho + Pi
        std::uint64_t t = st[1];
        for (int i = 0; i < 24; ++i) {
            int j = kPiLn[i];
            std::uint64_t tmp = st[j];
            st[j] = rotl64(t, kRotc[i]);
            t = tmp;
        }
        // Chi
        for (int j = 0; j < 25; j += 5) {
            std::uint64_t row[5];
            for (int i = 0; i < 5; ++i) row[i] = st[j + i];
            for (int i = 0; i < 5; ++i) st[j + i] ^= (~row[(i + 1) % 5]) & row[(i + 2) % 5];
        }
        // Iota
        st[0] ^= kRC[round];
    }
}

}  // namespace

Sponge::Sponge(std::uint8_t domain_suffix, std::size_t rate_bytes) noexcept
    : rate_(rate_bytes), domain_suffix_(domain_suffix) {}

void Sponge::absorb_block(const std::uint8_t* block) noexcept {
    auto* st_bytes = reinterpret_cast<std::uint8_t*>(state_);
    // Lane byte order is little-endian per Keccak's own spec; this target is
    // x86_64 (little-endian), so a direct byte-array XOR over the uint64_t
    // lanes is the correct mapping without an explicit endian swap.
    for (std::size_t i = 0; i < rate_; ++i) st_bytes[i] ^= block[i];
    keccak_f1600(state_);
}

void Sponge::absorb(std::span<const std::uint8_t> data) noexcept {
    const std::uint8_t* p = data.data();
    std::size_t n = data.size();
    while (n > 0) {
        const std::size_t take = std::min(n, rate_ - buf_len_);
        std::memcpy(buf_ + buf_len_, p, take);
        buf_len_ += take;
        p += take;
        n -= take;
        if (buf_len_ == rate_) {
            absorb_block(buf_);
            buf_len_ = 0;
        }
    }
}

void Sponge::squeeze(std::span<std::uint8_t> out) noexcept {
    if (!finalized_) {
        std::uint8_t pad[136] = {0};
        std::memcpy(pad, buf_, buf_len_);
        pad[buf_len_] ^= domain_suffix_;
        pad[rate_ - 1] ^= 0x80;
        absorb_block(pad);
        finalized_    = true;
        squeeze_pos_  = 0;  // absorb_block already permuted; state is ready to read from 0
    }
    auto* st_bytes = reinterpret_cast<std::uint8_t*>(state_);
    std::size_t produced = 0;
    while (produced < out.size()) {
        if (squeeze_pos_ == rate_) {
            keccak_f1600(state_);
            squeeze_pos_ = 0;
        }
        const std::size_t take = std::min(out.size() - produced, rate_ - squeeze_pos_);
        std::memcpy(out.data() + produced, st_bytes + squeeze_pos_, take);
        squeeze_pos_ += take;
        produced += take;
    }
}

void shake256(std::span<const std::uint8_t> data, std::span<std::uint8_t> out) noexcept {
    Sponge sp(0x1F);
    sp.absorb(data);
    sp.squeeze(out);
}

void cshake256(std::span<const std::uint8_t> data, std::span<std::uint8_t> out,
              std::string_view function_name, std::string_view customization) noexcept {
    if (function_name.empty() && customization.empty()) {
        shake256(data, out);
        return;
    }
    Sponge sp(0x04);
    const auto n_enc = encode_string(
        std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(function_name.data()),
                                      function_name.size()));
    const auto s_enc = encode_string(
        std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(customization.data()),
                                      customization.size()));
    // bytepad(encode_string(N) || encode_string(S), 136)
    std::vector<std::uint8_t> prefix = left_encode(136);
    prefix.insert(prefix.end(), n_enc.begin(), n_enc.end());
    prefix.insert(prefix.end(), s_enc.begin(), s_enc.end());
    const std::size_t pad_len = (136 - (prefix.size() % 136)) % 136;
    prefix.resize(prefix.size() + pad_len, 0);

    sp.absorb(prefix);
    sp.absorb(data);
    sp.squeeze(out);
}

std::vector<std::uint8_t> left_encode(std::uint64_t x) {
    if (x == 0) return {0x01, 0x00};
    std::uint8_t buf[8];
    for (int i = 0; i < 8; ++i) buf[i] = std::uint8_t(x >> (56 - 8 * i));
    int i = 0;
    while (i < 7 && buf[i] == 0) ++i;
    std::vector<std::uint8_t> out;
    out.push_back(std::uint8_t(8 - i));
    out.insert(out.end(), buf + i, buf + 8);
    return out;
}

std::vector<std::uint8_t> right_encode(std::uint64_t x) {
    if (x == 0) return {0x00, 0x01};
    std::uint8_t buf[8];
    for (int i = 0; i < 8; ++i) buf[i] = std::uint8_t(x >> (56 - 8 * i));
    int i = 0;
    while (i < 7 && buf[i] == 0) ++i;
    std::vector<std::uint8_t> out;
    out.insert(out.end(), buf + i, buf + 8);
    out.push_back(std::uint8_t(8 - i));
    return out;
}

std::vector<std::uint8_t> encode_string(std::span<const std::uint8_t> s) {
    auto out = left_encode(std::uint64_t(s.size()) * 8);
    out.insert(out.end(), s.begin(), s.end());
    return out;
}

}  // namespace lux::node::keccak
