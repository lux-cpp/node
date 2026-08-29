// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// mesh_vote_transport.hpp — consensus's VoteTransport realized over a FULL MESH
// of real TCP sockets, framed by the canonical ZAP wire codec (zap-cpp-core).
//
// The existing zap::ZapVoteTransport is single-peer (one fd) and holds Node*
// directly. node2 needs an N-peer mesh, and takes the chance to decomplect: this
// transport carries a vote SINK (std::function), not a Node — so it knows only
// sockets + ZAP framing + the vote codec. It has no Node type, no gate, no
// finality rule. The host supplies a sink wired to Node::onVote.
//
//   broadcast(v): this node's OWN vote. node.cpp relies on the transport echoing
//     a node's own vote back so its gate counts it (the gate dedups by voter key),
//     so we self-deliver through the sink, then write the ZAP frame to EVERY peer.
//   pump(): drain every peer's socket (non-blocking) through its FrameReader,
//     decode each complete vote frame, deliver via the sink. Returns the number
//     of votes delivered (progress signal for the driver / observability).
//
// A PEER IS A MEMBER, NOT A WALL — one eviction rule, stated once in `dead`:
// a peer whose stream closed, whose framing was violated, or whose socket will
// not take a write is DROPPED. The quorum rule already decides finality from
// whoever is left, so dropping a peer costs liveness nothing and removes every
// way one socket can hold the node: an unbounded buffer (the reader is capped
// and stops feeding once it rejects a stream), a corpse that is polled forever,
// or a stalled reader that blocks broadcast (the host sets a send timeout, so a
// write fails instead of hanging). Frames already reassembled are delivered
// BEFORE the peer is dropped, so a validator that votes and then disconnects
// still counts.
//
// Threading: in node2 each MeshVoteTransport is owned and driven by exactly one
// thread (its host), so there is no shared-mutable consensus state. The per-peer
// write mutex exists only to satisfy lux::zap::write_frame_locked's signature; it
// is uncontended here.

#pragma once

#include "lux/consensus/node.hpp"            // VoteTransport, SignedVote
#include "lux/consensus/zap/vote_codec.hpp"  // encode_vote/decode_vote, kVoteMsgType
#include "lux/node2/frame_reader.hpp"
#include "lux/zap/wire.hpp"                    // write_frame_locked, strip_flags

#include <csignal>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#include <unistd.h>  // close

namespace lux::node2 {

// The vote codec writes three length-framed fixed-width fields — 32 + 48 + 96
// bytes, each behind a 4-byte length — so a vote frame is exactly 188 bytes. A
// frame on this link is a vote or it is a lie, and the reader is told so: one
// page of headroom leaves room for the codec to grow without a negotiation while
// still bounding a hostile peer to 4 KiB of our memory instead of 16 MiB.
inline constexpr std::uint32_t kMaxVoteFrame = 4096;

// A peer that hangs up must not kill this validator. Writing to a closed TCP peer
// raises SIGPIPE, whose default disposition is process death — so any peer could
// end a node by disconnecting at the moment it was broadcast to. The write already
// reports EPIPE, and that return value is the whole signal the eviction rule needs.
// Disarmed once per process, from the one place in node2 that writes to a socket.
inline void ignore_sigpipe() {
    static const bool once = [] { return ::signal(SIGPIPE, SIG_IGN) != SIG_ERR; }();
    (void)once;
}

// Where decoded inbound (and self-echoed) votes go. Wiring this to Node::onVote
// instead of holding a Node* is what keeps the transport free of consensus.
using VoteSink = std::function<void(const lux::consensus::SignedVote&)>;

class MeshVoteTransport : public lux::consensus::VoteTransport {
public:
    explicit MeshVoteTransport(VoteSink sink) : sink_(std::move(sink)) { ignore_sigpipe(); }

    // The transport owns its peer fds: close them when it dies.
    ~MeshVoteTransport() override {
        for (auto& p : peers_)
            if (p->fd >= 0) ::close(p->fd);
    }

    MeshVoteTransport(const MeshVoteTransport&) = delete;
    MeshVoteTransport& operator=(const MeshVoteTransport&) = delete;

    // Register one connected peer stream socket. Called once per peer during mesh
    // setup, by the single setup thread — no locking needed.
    void add_peer(int fd) { peers_.push_back(std::make_unique<Peer>(fd)); }

    std::size_t peer_count() const noexcept { return peers_.size(); }
    // Peers dropped so far by the eviction rule (observability / tests).
    std::size_t evicted() const noexcept { return evicted_; }

    // VoteTransport: disseminate this node's own ACCEPT vote.
    void broadcast(const lux::consensus::SignedVote& v) override {
        sink_(v);  // self-echo: the originator's own vote must reach its own gate
        const std::vector<std::uint8_t> payload = lux::consensus::zap::encode_vote(v);
        for (std::size_t i = 0; i < peers_.size();) {
            Peer& p = *peers_[i];
            const bool sent = lux::zap::write_frame_locked(p.fd, p.wmu,
                                                           lux::consensus::zap::kVoteMsgType,
                                                           payload.data(), payload.size());
            if (sent) { ++i; continue; }
            drop(i);  // the socket will not take our vote — that peer is gone
        }
    }

    // Drain every peer; deliver each complete, structurally-valid vote frame.
    // Returns the number of votes delivered this call. Never blocks.
    std::size_t pump() {
        std::size_t delivered = 0;
        for (std::size_t i = 0; i < peers_.size();) {
            Peer& p = *peers_[i];
            const Drain d = p.rx.drain_fd(p.fd);
            // Deliver what completed BEFORE judging the peer: a validator that
            // voted and then hung up still counts toward the quorum.
            while (auto f = p.rx.next()) {
                if (lux::zap::strip_flags(f->msg_type) != lux::consensus::zap::kVoteMsgType)
                    continue;  // not a vote frame — ignore
                if (auto vote = lux::consensus::zap::decode_vote(f->payload)) {
                    sink_(*vote);  // structurally valid → hand to the gate (which verifies + dedups)
                    ++delivered;
                }
                // a structurally-invalid payload is silently dropped: a peer cannot
                // inject a malformed vote (decode_vote enforces exact field widths).
            }
            if (dead(d, p)) { drop(i); continue; }
            ++i;
        }
        return delivered;
    }

private:
    struct Peer {
        explicit Peer(int f) : fd(f), rx(kMaxVoteFrame) {}
        int fd;
        std::mutex wmu;  // serializes write_frame_locked on this fd (uncontended here)
        FrameReader rx;  // this peer's reassembly buffer, capped at one vote frame
    };

    // THE eviction rule: the stream ended, or it broke the framing contract.
    static bool dead(Drain d, const Peer& p) noexcept {
        return d == Drain::Closed || p.rx.error();
    }

    void drop(std::size_t i) {
        if (peers_[i]->fd >= 0) ::close(peers_[i]->fd);
        peers_.erase(peers_.begin() + static_cast<std::ptrdiff_t>(i));
        ++evicted_;
    }

    VoteSink sink_;
    std::vector<std::unique_ptr<Peer>> peers_;  // unique_ptr: Peer holds a non-movable mutex
    std::size_t evicted_ = 0;
};

}  // namespace lux::node2
