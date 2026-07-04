// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// frame_reader.hpp — a per-peer ZAP frame reassembler for NON-BLOCKING reads.
//
// WHY THIS EXISTS (and why we do not reuse lux::zap::read_frame here):
//   read_frame is built on read_exact, which (a) treats EAGAIN as a fatal error
//   and (b) blocks until a whole frame arrives. Neither is acceptable for a
//   single-threaded mesh pump that services N peers: a partially-arrived frame
//   on one peer must NOT block the others, and "no data right now" is the normal
//   case, not an error. FrameReader instead accumulates whatever bytes are ready
//   and yields a frame only once it is complete — so fragmentation is invisible
//   to the consensus layer and a slow peer never stalls the loop.
//
// This is the ONE place in node2 that knows non-blocking stream framing. It is
// orthogonal to the vote codec (which parses the payload) and to consensus.
//
// Wire layout (must match lux/zap/wire.hpp byte-for-byte):
//
//   [4-byte BE length][1-byte msg_type][`length` bytes payload]
//
// The byte-handling core (feed + next) is socket-free, so it is unit-testable by
// feeding arbitrary byte slices — including a frame split across many feeds and
// several frames in one feed. drain_fd is the thin non-blocking read on top.

#pragma once

#include "lux/zap/wire.hpp"  // HeaderSize, MaxMessageSize

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include <sys/socket.h>  // recv, MSG_DONTWAIT

namespace lux::node2 {

// One decoded ZAP frame: the raw 1-byte msg_type (response/error flags NOT
// stripped — the caller decides) and the payload bytes.
struct Frame {
    std::uint8_t msg_type = 0;
    std::vector<std::uint8_t> payload;
};

// Outcome of a non-blocking drain of a peer socket.
enum class Drain {
    Data,        // some bytes were read into the buffer
    WouldBlock,  // nothing available right now (EAGAIN) — normal, not an error
    Closed,      // peer closed the connection (EOF) or a hard I/O error
};

class FrameReader {
public:
    // ── socket-free core (unit-testable without a network) ───────────────────

    // Append freshly-read bytes to the reassembly buffer.
    void feed(const std::uint8_t* data, std::size_t len) {
        buf_.insert(buf_.end(), data, data + len);
    }

    // Pop the next complete frame, or nullopt if one is not yet fully buffered.
    // A length exceeding MaxMessageSize latches error() and yields nothing — a
    // peer cannot make us allocate an unbounded buffer.
    std::optional<Frame> next() {
        if (bad_) return std::nullopt;
        if (buf_.size() < lux::zap::HeaderSize) return std::nullopt;

        const std::uint32_t length =
            static_cast<std::uint32_t>(buf_[0]) << 24 |
            static_cast<std::uint32_t>(buf_[1]) << 16 |
            static_cast<std::uint32_t>(buf_[2]) << 8  |
            static_cast<std::uint32_t>(buf_[3]);
        if (length > lux::zap::MaxMessageSize) { bad_ = true; return std::nullopt; }

        const std::size_t need = lux::zap::HeaderSize + length;
        if (buf_.size() < need) return std::nullopt;  // frame not fully arrived yet

        Frame f;
        f.msg_type = buf_[4];
        f.payload.assign(buf_.begin() + lux::zap::HeaderSize, buf_.begin() + need);
        buf_.erase(buf_.begin(), buf_.begin() + need);
        return f;
    }

    bool error() const noexcept { return bad_; }
    std::size_t buffered() const noexcept { return buf_.size(); }

    // ── non-blocking socket drain on top of the core ─────────────────────────

    // Read every currently-available byte from `fd` into the buffer WITHOUT
    // blocking (MSG_DONTWAIT keeps the fd itself blocking — so writes elsewhere
    // stay robust — while this read returns immediately when the socket is dry).
    Drain drain_fd(int fd) {
        // Once an oversize length has latched error(), the stream is unusable and
        // MUST NOT keep growing buf_ — otherwise the MaxMessageSize guard in next()
        // is defeated (a peer streams past a bogus header → unbounded allocation).
        // Report Closed so the caller drops the peer.
        if (bad_) return Drain::Closed;
        std::uint8_t tmp[4096];
        bool any = false;
        for (;;) {
            const ssize_t r = ::recv(fd, tmp, sizeof tmp, MSG_DONTWAIT);
            if (r > 0) { feed(tmp, static_cast<std::size_t>(r)); any = true; continue; }
            if (r == 0) return Drain::Closed;  // orderly peer shutdown
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return any ? Drain::Data : Drain::WouldBlock;
            return Drain::Closed;  // hard error
        }
    }

private:
    std::vector<std::uint8_t> buf_;
    bool bad_ = false;
};

}  // namespace lux::node2
