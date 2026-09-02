// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// rlp.hpp — RLP DECODE, which is the half cevm does not have. `cevm::rlp`
// encodes (it is what the state trie writes leaves with); nothing in the stack
// reads RLP back, because until now nothing accepted a transaction from the
// outside. Decoding is exactly what `eth_sendRawTransaction` is.
//
// Each item is returned with BOTH its payload and the raw bytes it was encoded
// as. That is not a convenience: a transaction's signing preimage is the RLP of
// a PREFIX of its own item list, so re-serializing it from decoded values would
// mean re-deriving an encoding the sender already chose, and a single
// disagreement about minimality would recover the wrong sender. Concatenating
// the raw slices reproduces the sender's bytes exactly, by construction.
//
// It is a decoder for untrusted input, so every length is checked against what
// remains before it is used, and a truncated or over-long field is a nullopt
// rather than a read past the end.

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace lux::node::rlp {

// One decoded item: `payload` is its content, `raw` is the bytes it occupied
// (header included). `list` says which of the two RLP shapes it is.
struct Item {
    std::span<const std::uint8_t> payload;
    std::span<const std::uint8_t> raw;
    bool                          list = false;
};

// Decode ONE item at the head of `in`. Rejects a truncated header, a truncated
// body, and a non-minimal long-form length (leading zero byte), which is what
// stops two encodings of one value from both being accepted.
inline std::optional<Item> item(std::span<const std::uint8_t> in) noexcept {
    if (in.empty()) return std::nullopt;
    const std::uint8_t b = in[0];

    auto span_of = [&](std::size_t head, std::size_t len) -> std::optional<Item> {
        if (in.size() < head + len) return std::nullopt;
        Item it;
        it.payload = in.subspan(head, len);
        it.raw     = in.subspan(0, head + len);
        it.list    = b >= 0xc0;
        return it;
    };
    // Long-form length: `n` bytes of big-endian length, which must be minimal
    // (no leading zero) and must fit.
    auto long_len = [&](std::size_t n) -> std::optional<std::size_t> {
        if (n == 0 || n > 8 || in.size() < 1 + n) return std::nullopt;
        if (in[1] == 0) return std::nullopt;  // non-minimal
        std::size_t len = 0;
        for (std::size_t i = 0; i < n; ++i) len = (len << 8) | in[1 + i];
        if (len < 56) return std::nullopt;  // would have used the short form
        return len;
    };

    if (b <= 0x7f) {  // the byte is the item
        Item it;
        it.payload = in.subspan(0, 1);
        it.raw     = in.subspan(0, 1);
        return it;
    }
    if (b <= 0xb7) return span_of(1, b - 0x80u);                 // short string
    if (b <= 0xbf) {                                             // long string
        auto n = long_len(b - 0xb7u);
        return n ? span_of(1 + (b - 0xb7u), *n) : std::nullopt;
    }
    if (b <= 0xf7) return span_of(1, b - 0xc0u);                 // short list
    auto n = long_len(b - 0xf7u);                                // long list
    return n ? span_of(1 + (b - 0xf7u), *n) : std::nullopt;
}

// Decode every item inside a list's payload. Returns nullopt if any item is
// malformed or if the items do not exactly fill the payload — trailing bytes
// inside a list are a second encoding of the same list, so they are refused.
inline std::optional<std::vector<Item>> items(std::span<const std::uint8_t> payload) noexcept {
    std::vector<Item> out;
    while (!payload.empty()) {
        auto it = item(payload);
        if (!it) return std::nullopt;
        payload = payload.subspan(it->raw.size());
        out.push_back(*it);
    }
    return out;
}

// A scalar's value. RLP integers are minimal big-endian, so a leading zero byte
// (or a width past the target) is a malformed scalar, not a big number.
inline std::optional<std::uint64_t> u64(const Item& it) noexcept {
    if (it.list || it.payload.size() > 8) return std::nullopt;
    if (it.payload.size() > 1 && it.payload[0] == 0) return std::nullopt;
    std::uint64_t v = 0;
    for (auto c : it.payload) v = (v << 8) | c;
    return v;
}

// A scalar right-aligned into 32 bytes — how the EVM wants a value or a price.
inline std::optional<std::array<std::uint8_t, 32>> word(const Item& it) noexcept {
    if (it.list || it.payload.size() > 32) return std::nullopt;
    if (it.payload.size() > 1 && it.payload[0] == 0) return std::nullopt;
    std::array<std::uint8_t, 32> w{};
    std::copy(it.payload.begin(), it.payload.end(), w.end() - static_cast<std::ptrdiff_t>(it.payload.size()));
    return w;
}

// ── the encode half this file needs, and only that half ─────────────────────
// Re-wrapping a prefix of an item list as a list, and writing the three EIP-155
// scalars that are appended to it. cevm::rlp encodes values; these two write
// STRUCTURE around bytes that are already encoded, which is what a signing
// preimage is made of.

// The header for a list whose payload is `len` bytes.
inline std::vector<std::uint8_t> list_header(std::size_t len) {
    if (len < 56) return {static_cast<std::uint8_t>(0xc0 + len)};
    std::uint8_t be[8];
    std::size_t  n = 0;
    for (std::size_t v = len; v; v >>= 8) be[n++] = static_cast<std::uint8_t>(v & 0xff);
    std::vector<std::uint8_t> out{static_cast<std::uint8_t>(0xf7 + n)};
    for (std::size_t i = n; i-- > 0;) out.push_back(be[i]);
    return out;
}

// A minimal-big-endian scalar, as RLP.
inline std::vector<std::uint8_t> scalar(std::uint64_t v) {
    if (v == 0) return {0x80};
    std::uint8_t be[8];
    std::size_t  n = 0;
    for (std::uint64_t x = v; x; x >>= 8) be[n++] = static_cast<std::uint8_t>(x & 0xff);
    std::vector<std::uint8_t> body;
    for (std::size_t i = n; i-- > 0;) body.push_back(be[i]);
    if (body.size() == 1 && body[0] <= 0x7f) return body;
    std::vector<std::uint8_t> out{static_cast<std::uint8_t>(0x80 + body.size())};
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

}  // namespace lux::node::rlp
