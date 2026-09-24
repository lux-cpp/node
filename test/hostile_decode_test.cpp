// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// hostile_decode_test.cpp — the RLP decoder, fed bytes a stranger would send.
//
// rlp::item reads what a luxd peer puts on the p2p link (peer.cpp), so it is
// reachable by anyone who can open a connection. It may not abort, allocate on
// a number it was handed, or read past its buffer — a decoder that dies on bad
// input is a halt available to anyone who can reach one node.
//
// The EVM's own decoders — a transaction, a block — are the EVM plugin's, and
// are held to the same cases where the plugin is built.

#include "../src/rlp.hpp"   // the decoder itself, where the bound actually lives

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

using namespace lux::node;

namespace {

int g_fail = 0;
void check(bool ok, const std::string& what) {
    std::printf("  %s  %s\n", ok ? "ok  " : "FAIL", what.c_str());
    if (!ok) ++g_fail;
}

}  // namespace

int main() {
    std::printf("node — what a stranger can send the RLP decoder\n\n");

    // THE OVERFLOW, asserted where it lives: the bound is in rlp::item.
    //
    // 0xbf is a long string whose length is the next EIGHT bytes; all-0xff
    // declares 2^64-1. The header is 9 bytes, so a bound written as
    // `size < head + len` computes 9 + (2^64-1), which WRAPS to 8 — less than
    // the buffer — and the length is ACCEPTED, after which subspan is asked for
    // 18 exabytes. Written as `len > size - head` it cannot wrap.
    {
        std::vector<std::uint8_t> v{0xbf};
        for (int i = 0; i < 8; ++i) v.push_back(0xff);
        v.resize(64, 0xaa);
        check(!rlp::item(v).has_value(),
              "rlp::item refuses a declared length of 2^64-1 (the add-and-compare overflow)");
    }
    {
        std::vector<std::uint8_t> v{0xff};   // the same, as a LIST
        for (int i = 0; i < 8; ++i) v.push_back(0xff);
        v.resize(64, 0xaa);
        check(!rlp::item(v).has_value(), "rlp::item refuses the same overflow declared as a list");
    }
    // Every wrapping length: head is 9, so len in [2^64-8, 2^64-1] lands
    // head+len in [1, 8] and slips under a 64-byte buffer.
    {
        bool all_refused = true;
        for (int k = 1; k <= 8; ++k) {
            std::vector<std::uint8_t> v{0xbf};
            const std::uint64_t len = ~0ull - static_cast<std::uint64_t>(k) + 1;
            for (int i = 7; i >= 0; --i) v.push_back(std::uint8_t((len >> (i * 8)) & 0xff));
            v.resize(64, 0xaa);
            if (rlp::item(v).has_value()) all_refused = false;
        }
        check(all_refused, "rlp::item refuses every length that wraps the bound");
    }
    {
        std::vector<std::uint8_t> v{0xbf, 0x7f};
        for (int i = 0; i < 7; ++i) v.push_back(0xff);
        v.resize(64, 0xaa);
        check(!rlp::item(v).has_value(), "rlp::item refuses a huge-but-unwrapped declared length");
    }
    // A well-formed long string is still ACCEPTED — the bound rejects lies, not
    // length. Without this the two checks above would pass on a decoder that
    // refused everything.
    {
        std::vector<std::uint8_t> v{0xb8, 60};
        v.resize(62, 0xaa);
        const auto it = rlp::item(v);
        check(it.has_value() && it->payload.size() == 60,
              "rlp::item still accepts an honest 60-byte string");
    }

    std::printf("\n%s\n", g_fail ? "FAIL" : "PASS — hostile input is refused, not fatal");
    return g_fail ? 1 : 0;
}
