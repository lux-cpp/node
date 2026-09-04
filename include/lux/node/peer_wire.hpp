// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// peer_wire.hpp — luxd's OWN peer-to-peer codec: `luxfi/proto node/zap/p2p`, a
// positional encoding over TCP+TLS. NOT `luxfi/api/zap` (the plugin-RPC frame
// `MeshVoteTransport`/`FrameReader` already speak): two protocols share the
// "ZAP" name in this codebase and this file is deliberately independent of
// both existing wire modules rather than bent to fit either.
//
// Frame:
//
//   [4-byte BE length][1-byte tag][fields...]
//
// `length` COUNTS THE TAG BYTE — length = 1 + sum(field bytes). This is the
// one bit that differs from the plugin-RPC frame (`lux::zap::wire`, whose
// length excludes its type byte) and getting it backwards desyncs the stream
// on frame one.
//
// Field primitives, all big-endian, and EVERY byte-string field is length-
// prefixed even when its width never varies — a NodeID or a hash goes on the
// wire as `u32 len` then `len` raw bytes, not as a bare fixed array:
//
//   u8      1 byte
//   bool    1 byte, 1 == true, anything else == false
//   u32     4 bytes BE
//   u64     8 bytes BE
//   bytes   u32 BE length, then that many raw bytes
//   text    `bytes` of UTF-8
//   list_bytes   u32 BE count, then each element as `bytes`
//   list_u32     u32 BE count, then each element as `u32`
//   absent()     the single byte 0x00  (an Option-like field, None)
//   present()    the single byte 0x01  (an Option-like field, Some — the
//                encoded value follows immediately, written by the caller)
//
// Ported from lux-rs/node's `src/wire.rs`, itself conformance-tested against a
// live luxd — this file does not re-derive the shape, it reproduces it.

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace lux::node::peer_wire {

// The 2 MiB cap luxd itself enforces on one frame body (post-decompression).
inline constexpr std::uint32_t kMessageMax = 2u * 1024u * 1024u;

// Message tags — `luxfi/proto node/zap/p2p`'s `codec.go`, values 1..26.
enum class Tag : std::uint8_t {
    CompressedZstd        = 1,
    Ping                  = 2,
    Pong                  = 3,
    Handshake             = 4,
    GetPeerList           = 5,
    PeerList              = 6,
    GetStateSummaryFrontier    = 7,
    StateSummaryFrontier       = 8,
    GetAcceptedStateSummary    = 9,
    AcceptedStateSummary       = 10,
    GetAcceptedFrontier   = 11,
    AcceptedFrontier      = 12,
    GetAccepted           = 13,
    Accepted              = 14,
    GetAncestors          = 15,
    Ancestors             = 16,
    Get                   = 17,
    Put                   = 18,
    PushQuery             = 19,
    PullQuery             = 20,
    Chits                 = 21,
    Request               = 22,
    Response              = 23,
    Gossip                = 24,
    Error                 = 25,
    BFT                   = 26,
};

// A field-order writer. Appends only — nothing here interprets what it writes,
// so a caller cannot get the field TYPES wrong in a way this class would hide,
// only the field ORDER, which is on the caller exactly as it is in Go's struct
// declaration.
class Writer {
public:
    void u8(std::uint8_t v) { buf_.push_back(v); }
    void boolean(bool v) { buf_.push_back(v ? 1 : 0); }
    void u32(std::uint32_t v) {
        buf_.push_back(std::uint8_t(v >> 24));
        buf_.push_back(std::uint8_t(v >> 16));
        buf_.push_back(std::uint8_t(v >> 8));
        buf_.push_back(std::uint8_t(v));
    }
    void u64(std::uint64_t v) {
        for (int s = 56; s >= 0; s -= 8) buf_.push_back(std::uint8_t(v >> s));
    }
    void bytes(std::span<const std::uint8_t> v) {
        u32(std::uint32_t(v.size()));
        buf_.insert(buf_.end(), v.begin(), v.end());
    }
    void text(std::string_view v) {
        bytes(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(v.data()), v.size()));
    }
    void list_bytes(const std::vector<std::vector<std::uint8_t>>& items) {
        u32(std::uint32_t(items.size()));
        for (const auto& it : items) bytes(it);
    }
    void list_u32(const std::vector<std::uint32_t>& items) {
        u32(std::uint32_t(items.size()));
        for (auto v : items) u32(v);
    }
    void absent() { buf_.push_back(0x00); }
    void present() { buf_.push_back(0x01); }

    // One frame: [4B BE length = 1+body.size()][tag][body], length includes tag.
    [[nodiscard]] std::vector<std::uint8_t> frame(Tag tag) const {
        std::vector<std::uint8_t> out;
        const std::uint32_t length = std::uint32_t(1 + buf_.size());
        out.push_back(std::uint8_t(length >> 24));
        out.push_back(std::uint8_t(length >> 16));
        out.push_back(std::uint8_t(length >> 8));
        out.push_back(std::uint8_t(length));
        out.push_back(std::uint8_t(tag));
        out.insert(out.end(), buf_.begin(), buf_.end());
        return out;
    }

private:
    std::vector<std::uint8_t> buf_;
};

// A field-order reader over one already-length-delimited frame BODY (the bytes
// after the 4-byte length prefix, tag included at body[0]). Every accessor
// reports failure by throwing `Truncated` rather than reading past the end —
// this decodes bytes a stranger (or a version skew) sent.
struct Truncated : std::runtime_error {
    Truncated() : std::runtime_error("peer_wire: frame truncated") {}
};
struct Oversize : std::runtime_error {
    Oversize() : std::runtime_error("peer_wire: field exceeds message cap") {}
};

class Reader {
public:
    explicit Reader(std::span<const std::uint8_t> body) : d_(body) {}

    [[nodiscard]] std::size_t remaining() const noexcept { return d_.size() - at_; }

    Tag tag() {
        if (remaining() < 1) throw Truncated{};
        return Tag(d_[at_++]);
    }
    std::uint8_t u8() {
        if (remaining() < 1) throw Truncated{};
        return d_[at_++];
    }
    bool boolean() { return u8() == 1; }
    std::uint32_t u32() {
        if (remaining() < 4) throw Truncated{};
        std::uint32_t v = (std::uint32_t(d_[at_]) << 24) | (std::uint32_t(d_[at_ + 1]) << 16) |
                          (std::uint32_t(d_[at_ + 2]) << 8) | std::uint32_t(d_[at_ + 3]);
        at_ += 4;
        return v;
    }
    std::uint64_t u64() {
        if (remaining() < 8) throw Truncated{};
        std::uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v = (v << 8) | d_[at_ + std::size_t(i)];
        at_ += 8;
        return v;
    }
    std::vector<std::uint8_t> bytes() {
        const std::uint32_t len = u32();
        if (len > kMessageMax) throw Oversize{};
        if (remaining() < len) throw Truncated{};
        std::vector<std::uint8_t> out(d_.begin() + std::ptrdiff_t(at_), d_.begin() + std::ptrdiff_t(at_ + len));
        at_ += len;
        return out;
    }
    std::string text() {
        auto b = bytes();
        return std::string(b.begin(), b.end());
    }
    std::vector<std::vector<std::uint8_t>> list_bytes() {
        const std::uint32_t n = u32();
        if (n > kMessageMax) throw Oversize{};  // cannot exceed the frame cap element-for-element
        std::vector<std::vector<std::uint8_t>> out;
        out.reserve(n);
        for (std::uint32_t i = 0; i < n; ++i) out.push_back(bytes());
        return out;
    }
    std::vector<std::uint32_t> list_u32() {
        const std::uint32_t n = u32();
        if (n > kMessageMax / 4) throw Oversize{};
        std::vector<std::uint32_t> out;
        out.reserve(n);
        for (std::uint32_t i = 0; i < n; ++i) out.push_back(u32());
        return out;
    }
    // Option-like field: true if `present()` was written, false if `absent()`.
    bool option() { return boolean(); }

private:
    std::span<const std::uint8_t> d_;
    std::size_t                   at_ = 0;
};

}  // namespace lux::node::peer_wire
