// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// frame_reader_test.cpp — the reassembler in isolation, no sockets. Proves it is
// orthogonal: fragmentation and batching are handled purely at the byte layer,
// so the mesh/consensus layers above never see a partial frame.

#include "lux/node2/frame_reader.hpp"
#include "lux/zap/wire.hpp"

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

using namespace lux::node2;

namespace {
int g_fail = 0;
void check(bool ok, const std::string& what) {
    if (!ok) { std::printf("    ASSERT FAILED: %s\n", what.c_str()); ++g_fail; }
}

// Encode one ZAP frame [4-byte BE len][type][payload] exactly as write_frame does.
std::vector<std::uint8_t> frame(std::uint8_t type, const std::vector<std::uint8_t>& payload) {
    std::vector<std::uint8_t> f;
    const std::uint32_t n = static_cast<std::uint32_t>(payload.size());
    f.push_back(std::uint8_t(n >> 24));
    f.push_back(std::uint8_t(n >> 16));
    f.push_back(std::uint8_t(n >> 8));
    f.push_back(std::uint8_t(n));
    f.push_back(type);
    f.insert(f.end(), payload.begin(), payload.end());
    return f;
}
}  // namespace

int main() {
    std::printf("================ node2 — FrameReader (non-blocking reassembler) ================\n");

    // [1] a whole frame fed at once round-trips.
    {
        FrameReader r;
        const std::vector<std::uint8_t> body{1, 2, 3, 4, 5};
        const auto f = frame(0x11, body);
        r.feed(f.data(), f.size());
        auto got = r.next();
        check(got.has_value(), "one whole frame yields a frame");
        check(got && got->msg_type == 0x11 && got->payload == body, "type + payload intact");
        check(!r.next().has_value(), "buffer empty after the single frame");
    }

    // [2] a frame split byte-by-byte across feeds: nothing emitted until complete.
    {
        FrameReader r;
        const std::vector<std::uint8_t> body{0xAA, 0xBB, 0xCC};
        const auto f = frame(0x11, body);
        for (std::size_t i = 0; i + 1 < f.size(); ++i) {
            r.feed(&f[i], 1);
            check(!r.next().has_value(), "partial frame yields nothing at byte " + std::to_string(i));
        }
        r.feed(&f.back(), 1);  // final byte completes it
        auto got = r.next();
        check(got && got->payload == body, "frame emerges exactly when the last byte arrives");
    }

    // [3] several frames in one feed, plus a trailing partial: drain all whole
    //     frames, keep the partial buffered for later.
    {
        FrameReader r;
        const auto a = frame(0x11, {1});
        const auto b = frame(0x11, {2, 2});
        const auto c = frame(0x11, {3, 3, 3});
        std::vector<std::uint8_t> batch;
        batch.insert(batch.end(), a.begin(), a.end());
        batch.insert(batch.end(), b.begin(), b.end());
        batch.insert(batch.end(), c.begin(), c.begin() + 2);  // c is only half-present
        r.feed(batch.data(), batch.size());

        auto g1 = r.next(); auto g2 = r.next();
        check(g1 && g1->payload == std::vector<std::uint8_t>{1}, "first batched frame");
        check(g2 && g2->payload == std::vector<std::uint8_t>{2, 2}, "second batched frame");
        check(!r.next().has_value(), "third frame still partial — not yet yielded");
        r.feed(&c[2], c.size() - 2);  // deliver the rest of c
        auto g3 = r.next();
        check(g3 && g3->payload == std::vector<std::uint8_t>{3, 3, 3}, "third frame completes");
    }

    // [4] an oversize length header is rejected without allocating.
    {
        FrameReader r;
        const std::uint32_t huge = lux::zap::MaxMessageSize + 1;
        std::uint8_t hdr[5] = {std::uint8_t(huge >> 24), std::uint8_t(huge >> 16),
                               std::uint8_t(huge >> 8), std::uint8_t(huge), 0x11};
        r.feed(hdr, sizeof hdr);
        check(!r.next().has_value() && r.error(), "oversize frame rejected, error latched");
    }

    std::printf("-------------------------------------------------------------------------------\n");
    if (g_fail) { std::printf("==== FrameReader: FAIL (%d) ====\n", g_fail); return 1; }
    std::printf("==== FrameReader: PASS — fragmentation & batching handled at the byte layer ====\n");
    return 0;
}
